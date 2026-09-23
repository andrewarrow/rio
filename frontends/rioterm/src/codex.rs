use std::path::PathBuf;

/// Tracks whether Codex below one terminal is actively handling a prompt.
/// The macOS implementation follows Codex's session transcript; other
/// platforms keep the feature inert until they expose an equivalent API.
pub struct ActivityMonitor {
    #[cfg(target_os = "macos")]
    inner: macos::Monitor,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivityState {
    pub running: bool,
    pub needs_refresh: bool,
}

impl Default for ActivityMonitor {
    fn default() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            inner: macos::Monitor::default(),
        }
    }
}

impl ActivityMonitor {
    pub fn note_prompt_submitted(&mut self, shell_pid: u32) -> ActivityState {
        #[cfg(target_os = "macos")]
        return self.inner.note_prompt_submitted(shell_pid);

        #[cfg(not(target_os = "macos"))]
        {
            let _ = shell_pid;
            ActivityState::default()
        }
    }

    pub fn note_prompt_aborted(&mut self, shell_pid: u32) -> ActivityState {
        #[cfg(target_os = "macos")]
        return self.inner.note_prompt_aborted(shell_pid);

        #[cfg(not(target_os = "macos"))]
        {
            let _ = shell_pid;
            ActivityState::default()
        }
    }

    pub fn activity(&mut self, shell_pid: u32) -> ActivityState {
        #[cfg(target_os = "macos")]
        return self.inner.activity(shell_pid);

        #[cfg(not(target_os = "macos"))]
        {
            let _ = shell_pid;
            ActivityState::default()
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{ActivityState, PathBuf};
    use serde_json::Value;
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom};
    use std::mem;
    use std::path::Path;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    // The first process/transcript probe can race Codex spawning its worker or
    // creating the session file. Keep the probe alive long enough to cover
    // that handoff, but let ordinary shell input settle quickly.
    const PROMPT_PROBE_GRACE: Duration = Duration::from_secs(8);
    // Once a Codex process is found, allow a quiet startup phase (for example
    // image loading) before giving up if no task_started event is visible yet.
    const TASK_START_GRACE: Duration = Duration::from_secs(30);
    const PROCESS_MISSING_GRACE: Duration = Duration::from_secs(2);
    const EVENT_TIME_SKEW: Duration = Duration::from_secs(2);
    const TRANSCRIPT_READ_LIMIT: usize = 256 * 1024;
    const PROC_ALL_PIDS: u32 = 1;

    #[derive(Default)]
    pub(super) struct Monitor {
        process_id: Option<libc::pid_t>,
        process_started_at: Option<SystemTime>,
        transcript_path: Option<PathBuf>,
        transcript_offset: u64,
        pending_transcript_data: Vec<u8>,
        prompt_is_running: bool,
        prompt_submission_deadline: Option<Instant>,
        prompt_submitted_at: Option<SystemTime>,
        process_last_seen: Option<Instant>,
    }

    impl Monitor {
        pub(super) fn note_prompt_submitted(&mut self, shell_pid: u32) -> ActivityState {
            let process = codex_process(shell_pid as libc::pid_t);
            if let Some(process) = process.as_ref() {
                self.set_process(process);
                self.process_last_seen = Some(Instant::now());
            }

            self.prompt_is_running = process.is_some();
            self.prompt_submitted_at = Some(SystemTime::now());
            self.prompt_submission_deadline = Some(
                Instant::now()
                    + if process.is_some() {
                        TASK_START_GRACE
                    } else {
                        PROMPT_PROBE_GRACE
                    },
            );

            self.state()
        }

        pub(super) fn note_prompt_aborted(&mut self, shell_pid: u32) -> ActivityState {
            let _ = shell_pid;
            self.finish_prompt();
            self.state()
        }

        pub(super) fn activity(&mut self, shell_pid: u32) -> ActivityState {
            let now = Instant::now();
            let process = codex_process(shell_pid as libc::pid_t);

            if let Some(process) = process.as_ref() {
                self.set_process(process);
                self.process_last_seen = Some(now);

                if self.prompt_submission_deadline.is_some() {
                    self.prompt_is_running = true;
                }

                if self.transcript_path.is_none() {
                    self.transcript_path = find_transcript(process);
                }
                if let Some(path) = self.transcript_path.clone() {
                    self.read_new_events(&path);
                }
            } else if self.process_last_seen.is_none_or(|last_seen| {
                now.duration_since(last_seen) > PROCESS_MISSING_GRACE
            }) && self.prompt_submission_deadline.is_none()
            {
                self.finish_prompt();
            }

            if self
                .prompt_submission_deadline
                .is_some_and(|deadline| deadline <= now)
            {
                self.finish_prompt();
            }

            self.state()
        }

        fn set_process(&mut self, process: &CodexProcess) {
            if self.process_id != Some(process.id)
                || self.process_started_at != Some(process.started_at)
            {
                self.reset_process(Some(process));
            }
        }

        fn reset_process(&mut self, process: Option<&CodexProcess>) {
            self.process_id = process.map(|process| process.id);
            self.process_started_at = process.map(|process| process.started_at);
            self.transcript_path = None;
            self.transcript_offset = 0;
            self.pending_transcript_data.clear();
        }

        fn finish_prompt(&mut self) {
            self.prompt_is_running = false;
            self.prompt_submission_deadline = None;
            self.prompt_submitted_at = None;
            self.process_last_seen = None;
        }

        fn state(&self) -> ActivityState {
            ActivityState {
                running: self.prompt_is_running,
                needs_refresh: self.prompt_is_running
                    || self.prompt_submission_deadline.is_some(),
            }
        }

        fn read_new_events(&mut self, path: &Path) {
            let Ok(mut file) = File::open(path) else {
                return;
            };
            let Ok(file_size) = file.metadata().map(|metadata| metadata.len()) else {
                return;
            };

            if file_size < self.transcript_offset {
                self.transcript_offset = 0;
                self.pending_transcript_data.clear();
            }
            if file_size == self.transcript_offset {
                return;
            }
            if file.seek(SeekFrom::Start(self.transcript_offset)).is_err() {
                return;
            }

            let mut new_data = Vec::new();
            if file.read_to_end(&mut new_data).is_err() || new_data.is_empty() {
                return;
            }
            self.transcript_offset += new_data.len() as u64;
            self.pending_transcript_data.extend(new_data);

            while let Some(newline) = self
                .pending_transcript_data
                .iter()
                .position(|byte| *byte == b'\n')
            {
                let line: Vec<u8> =
                    self.pending_transcript_data.drain(..=newline).collect();
                let line = line.strip_suffix(&[b'\n']).unwrap_or(&line);
                if line.is_empty() {
                    continue;
                }

                let Ok(envelope) = serde_json::from_slice::<Value>(line) else {
                    continue;
                };
                if envelope.get("type").and_then(Value::as_str) != Some("event_msg") {
                    continue;
                }

                let Some(payload) = envelope.get("payload") else {
                    continue;
                };
                let Some(event_type) = payload.get("type").and_then(Value::as_str) else {
                    continue;
                };
                if !self.event_belongs_to_submitted_prompt(payload) {
                    continue;
                }

                match event_type {
                    "task_started" => {
                        self.prompt_submission_deadline = None;
                        self.prompt_is_running = true;
                    }
                    "task_complete" | "turn_aborted" => {
                        self.finish_prompt();
                    }
                    _ => {}
                }
            }
        }

        fn event_belongs_to_submitted_prompt(&self, payload: &Value) -> bool {
            let Some(submitted_at) = self.prompt_submitted_at else {
                return true;
            };
            let Some(timestamp) = payload
                .get("started_at")
                .or_else(|| payload.get("completed_at"))
                .and_then(Value::as_u64)
            else {
                // Current Codex lifecycle events carry timestamps. If a
                // future version omits one, the pending state is safer than
                // allowing an old completion record to hide a live spinner.
                return self.prompt_submission_deadline.is_none();
            };

            let Some(event_at) = UNIX_EPOCH.checked_add(Duration::from_secs(timestamp))
            else {
                return false;
            };
            event_at
                .checked_add(EVENT_TIME_SKEW)
                .is_some_and(|event_at| event_at >= submitted_at)
        }
    }

    struct CodexProcess {
        id: libc::pid_t,
        started_at: SystemTime,
        current_directory: PathBuf,
        arguments: Vec<String>,
    }

    struct ProcessInfo {
        parent_id: libc::pid_t,
        name: String,
        arguments: Vec<String>,
        started_at: SystemTime,
    }

    fn codex_process(root_pid: libc::pid_t) -> Option<CodexProcess> {
        if root_pid <= 0 {
            return None;
        }

        let processes = all_processes();
        let mut children_by_parent: HashMap<libc::pid_t, Vec<libc::pid_t>> =
            HashMap::new();
        for (pid, info) in &processes {
            children_by_parent
                .entry(info.parent_id)
                .or_default()
                .push(*pid);
        }

        let mut pending = children_by_parent.remove(&root_pid).unwrap_or_default();
        let mut launcher_match = None;
        while let Some(pid) = pending.pop() {
            let Some(info) = processes.get(&pid) else {
                continue;
            };

            let is_native_codex = is_codex_process_name(&info.name);
            let is_codex_launcher = info.arguments.iter().any(|argument| {
                Path::new(argument)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        let name = name.to_ascii_lowercase();
                        name == "codex" || name == "codex.js"
                    })
            });

            if is_native_codex || is_codex_launcher {
                if let Some(directory) = current_directory(pid) {
                    let match_process = CodexProcess {
                        id: pid,
                        started_at: info.started_at,
                        current_directory: directory,
                        arguments: info.arguments.clone(),
                    };
                    if is_native_codex {
                        return Some(match_process);
                    }
                    if launcher_match.is_none() {
                        launcher_match = Some(match_process);
                    }
                }
            }

            if let Some(children) = children_by_parent.get(&pid) {
                pending.extend(children.iter().copied());
            }
        }

        launcher_match
    }

    fn all_processes() -> HashMap<libc::pid_t, ProcessInfo> {
        let requested_size =
            unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
        if requested_size <= 0 {
            return HashMap::new();
        }

        let pid_count = requested_size as usize / mem::size_of::<libc::pid_t>() + 1;
        let mut pids = vec![0 as libc::pid_t; pid_count];
        let actual_size = unsafe {
            libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                pids.as_mut_ptr().cast(),
                (pids.len() * mem::size_of::<libc::pid_t>()) as i32,
            )
        };
        if actual_size <= 0 {
            return HashMap::new();
        }

        let count = actual_size as usize / mem::size_of::<libc::pid_t>();
        let mut result = HashMap::new();
        for &pid in pids.iter().take(count).filter(|pid| **pid > 0) {
            let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
            let read_size = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    (&mut info as *mut libc::proc_bsdinfo).cast(),
                    mem::size_of::<libc::proc_bsdinfo>() as i32,
                )
            };
            if read_size != mem::size_of::<libc::proc_bsdinfo>() as i32 {
                continue;
            }

            let name = unsafe { CStr::from_ptr(info.pbi_comm.as_ptr()) }
                .to_string_lossy()
                .to_ascii_lowercase();
            let arguments = if name == "node" || is_codex_process_name(&name) {
                process_arguments(pid)
            } else {
                Vec::new()
            };
            let started_at = UNIX_EPOCH
                + Duration::from_secs(info.pbi_start_tvsec)
                + Duration::from_micros(info.pbi_start_tvusec);
            result.insert(
                pid,
                ProcessInfo {
                    parent_id: info.pbi_ppid as libc::pid_t,
                    name,
                    arguments,
                    started_at,
                },
            );
        }
        result
    }

    fn is_codex_process_name(name: &str) -> bool {
        // Release builds normally appear as `codex`/`codex-*`; local Cargo
        // builds use `rust-codex`. Keep this name-based check narrow enough
        // that unrelated processes cannot turn every shell into a spinner.
        name == "codex"
            || name.starts_with("codex-")
            || name == "rust-codex"
            || name.starts_with("rust-codex-")
    }

    fn current_directory(pid: libc::pid_t) -> Option<PathBuf> {
        let mut info: libc::proc_vnodepathinfo = unsafe { mem::zeroed() };
        let read_size = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                (&mut info as *mut libc::proc_vnodepathinfo).cast(),
                mem::size_of::<libc::proc_vnodepathinfo>() as i32,
            )
        };
        if read_size != mem::size_of::<libc::proc_vnodepathinfo>() as i32 {
            return None;
        }

        let path = unsafe { CStr::from_ptr(info.pvi_cdir.vip_path.as_ptr().cast()) }
            .to_string_lossy()
            .into_owned();
        Some(PathBuf::from(path))
    }

    fn process_arguments(pid: libc::pid_t) -> Vec<String> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut size = 0;
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 || size <= mem::size_of::<libc::c_int>() {
            return Vec::new();
        }

        let mut bytes = vec![0u8; size as usize];
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                bytes.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 {
            return Vec::new();
        }

        bytes[mem::size_of::<libc::c_int>()..size as usize]
            .split(|byte| *byte == 0)
            .filter_map(|argument| String::from_utf8(argument.to_vec()).ok())
            .map(|argument| argument.to_ascii_lowercase())
            .collect()
    }

    fn find_transcript(process: &CodexProcess) -> Option<PathBuf> {
        let root = dirs::home_dir()?.join(".codex").join("sessions");
        let mut dates = Vec::new();
        if let Some(directory) = date_directory(&root, process.started_at) {
            dates.push(directory);
        }
        if let Some(directory) = date_directory(&root, SystemTime::now()) {
            if !dates.contains(&directory) {
                dates.push(directory);
            }
        }

        let process_directory = normalize_directory(&process.current_directory);
        let mut candidates = Vec::new();
        for directory in dates {
            let Ok(entries) = fs::read_dir(directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
                    continue;
                }
                let Some(directory) = transcript_working_directory(&path) else {
                    continue;
                };
                if normalize_directory(&directory) != process_directory {
                    continue;
                }
                let modified_at = entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .unwrap_or(UNIX_EPOCH);
                candidates.push((path, modified_at));
            }
        }

        let recent_cutoff = process
            .started_at
            .checked_sub(Duration::from_secs(300))
            .unwrap_or(UNIX_EPOCH);
        candidates
            .iter()
            .filter(|(_, modified_at)| *modified_at >= recent_cutoff)
            .max_by_key(|(_, modified_at)| *modified_at)
            .map(|(path, _)| path.clone())
            .or_else(|| {
                if process
                    .arguments
                    .iter()
                    .any(|argument| argument == "resume")
                {
                    candidates
                        .iter()
                        .filter(|(_, modified_at)| *modified_at >= process.started_at)
                        .max_by_key(|(_, modified_at)| *modified_at)
                        .map(|(path, _)| path.clone())
                } else {
                    None
                }
            })
    }

    fn date_directory(root: &Path, time: SystemTime) -> Option<PathBuf> {
        let seconds = time.duration_since(UNIX_EPOCH).ok()?.as_secs() as libc::time_t;
        let mut local = unsafe { mem::zeroed::<libc::tm>() };
        if unsafe { libc::localtime_r(&seconds, &mut local) }.is_null() {
            return None;
        }
        Some(
            root.join(format!("{:04}", local.tm_year + 1900))
                .join(format!("{:02}", local.tm_mon + 1))
                .join(format!("{:02}", local.tm_mday)),
        )
    }

    fn transcript_working_directory(path: &Path) -> Option<PathBuf> {
        let mut file = File::open(path).ok()?;
        let mut data = vec![0u8; TRANSCRIPT_READ_LIMIT];
        let count = file.read(&mut data).ok()?;
        let line = data[..count].split(|byte| *byte == b'\n').next()?;
        let envelope = serde_json::from_slice::<Value>(line).ok()?;
        if envelope.get("type").and_then(Value::as_str) != Some("session_meta") {
            return None;
        }
        envelope
            .get("payload")
            .and_then(|payload| payload.get("cwd"))
            .and_then(Value::as_str)
            .map(PathBuf::from)
    }

    fn normalize_directory(path: &Path) -> PathBuf {
        fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    }

    #[cfg(test)]
    mod tests {
        use super::is_codex_process_name;

        #[test]
        fn recognizes_release_and_development_codex_names() {
            assert!(is_codex_process_name("codex"));
            assert!(is_codex_process_name("codex-tui"));
            assert!(is_codex_process_name("rust-codex"));
            assert!(is_codex_process_name("rust-codex-debug"));
        }

        #[test]
        fn rejects_unrelated_process_names() {
            assert!(!is_codex_process_name("node"));
            assert!(!is_codex_process_name("code"));
            assert!(!is_codex_process_name("codexhelper"));
        }
    }
}

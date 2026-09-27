# Local macOS debug builds

`make app-aarch64-debug` creates `target/debug/osx/Rio.app`. To keep macOS
privacy approvals across rebuilds, sign it with a consistent certificate.
The default ad-hoc signature identifies a particular build, so changing the
binary can require approving Photos, Downloads, Music, and other access again.

List your code-signing identities:

```sh
security find-identity -v -p codesigning
```

Choose a valid Apple Development identity and put its SHA-1 identifier in
`Makefile.local` at the repository root (this file is ignored by Git):

```make
MACOS_DEBUG_SIGN_IDENTITY = YOUR_CERTIFICATE_SHA1
```

Then build normally:

```sh
make app-aarch64-debug
open target/debug/osx/Rio.app
```

Quit the previous app before rebuilding and reopening it. After switching from
ad-hoc signing, approve the requested access once more in macOS System Settings
> Privacy & Security. Continue launching the same app bundle and using the same
signing identity. Subsequent rebuilds should retain those approvals. macOS still
controls permissions; resetting privacy settings or changing the app's signing
identity can require approval again. Signing does not grant permissions itself.

If the configured certificate is unavailable, signing fails rather than silently
falling back to ad-hoc signing. You can explicitly opt into an ad-hoc build with
`make app-aarch64-debug MACOS_DEBUG_SIGN_IDENTITY=-`.

See Apple's [code signing requirements documentation](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
for how macOS identifies successive versions of an app.

# Tree desktop

Compose for desktop (JVM). The Rust client (`crates/tree-ffi`) is built by
cargo during the Gradle build and reached through the generated UniFFI
Kotlin bindings (JNA).

```sh
cd apps/desktop
gradle run                       # the app (needs a display)
sh ../../scripts/desktop_test.sh # from the repo root: model tests + off-screen screenshots
```

- `AppModel.kt`: everything the screens need, no UI code; tested against a
  real server.
- `Ui.kt`: the screens. `Strings.kt`: Korean and English text.
- The profile lives in `~/.tree/profile.db`, encrypted with the passphrase
  (Argon2id + SQLCipher in the core).
- QR codes (`QrUi.kt`, APP_PROTOCOL.md 6.5): a new computer shows its device
  link as a large QR code with the text and a copy button; settings show
  the username link's QR code. The desktop does not scan: the JVM has no
  camera API that works reliably on every system, so linking a new device
  from a computer means pasting the new device's link text.

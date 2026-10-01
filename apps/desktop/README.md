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

# Tree for Android

Kotlin + Compose. Shares the model and texts with the desktop app
(`apps/shared`). The Rust client is cross-compiled with the NDK.

```sh
sh scripts/android_lib.sh             # from the repo root: libtree_ffi.so for arm64-v8a and x86_64
cd apps/android && gradle assembleDebug  # needs ANDROID_HOME (SDK 35, build-tools 35)
```

Security settings honoured by the app: `chat.screenshot_block` and
`user.app_switcher_blur` set `FLAG_SECURE` (no screenshots, blank preview in
the app switcher); the encrypted profile is excluded from cloud backup and
device transfer (keys never leave the device; recovery uses the phrase).
Opening a `tree://join/...` link asks to join that group.

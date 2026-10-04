# Tree for Android

Kotlin + Compose. Shares the model and texts with the desktop app
(`apps/shared`). The Rust client is cross-compiled with the NDK.

```sh
sh scripts/android_lib.sh             # from the repo root: libtree_ffi.so for arm64-v8a and x86_64
cd apps/android && gradle assembleDebug  # needs ANDROID_HOME (SDK 35, build-tools 35)
```

Toolchain (Linux, used here):

```sh
mkdir -p /opt/android-sdk && cd /opt/android-sdk
# download the Linux "command-line tools only" archive from the official Android SDK page, then:
unzip -q commandlinetools-linux-*.zip && mkdir -p cmdline-tools/latest && mv cmdline-tools/bin cmdline-tools/lib cmdline-tools/latest/
yes | cmdline-tools/latest/bin/sdkmanager --sdk_root=/opt/android-sdk --licenses
cmdline-tools/latest/bin/sdkmanager --sdk_root=/opt/android-sdk "platforms;android-35" "build-tools;35.0.0" "ndk;27.3.13750724"
rustup target add aarch64-linux-android x86_64-linux-android
```

Security settings honoured by the app (APP_PROTOCOL.md 6.3):
`chat.screenshot_block` sets `FLAG_SECURE` while such a chat is open;
`user.app_switcher_blur` hides the recent-apps snapshot (Android 13+:
`setRecentsScreenshotEnabled(false)`, screenshots stay allowed; older:
`FLAG_SECURE` while in the background); `user.incognito_keyboard` sets
`IME_FLAG_NO_PERSONALIZED_LEARNING` on every text field; `user.app_lock`
unlocks with the passphrase, a PIN (with a keystore-held device secret) or
biometrics (Android 11+, keystore key bound to a strong biometric). Push
wake-ups come through a distributor app (open broadcast protocol, no
vendor library) or, without one, a periodic job; a locked profile only
gets a content-free notification. The encrypted profile is excluded from
cloud backup and device transfer (keys never leave the device; recovery
uses the phrase). None of these were run on a device here (no emulator):
they compile and the decisions are tested on the desktop.
Opening a `tree://join/...` link asks to join that group.

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

Security settings honoured by the app: `chat.screenshot_block` and
`user.app_switcher_blur` set `FLAG_SECURE` (no screenshots, blank preview in
the app switcher); the encrypted profile is excluded from cloud backup and
device transfer (keys never leave the device; recovery uses the phrase).
Opening a `tree://join/...` link asks to join that group.

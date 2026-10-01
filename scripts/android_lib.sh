#!/bin/sh
# Cross-compiles the Rust client library (tree-ffi) for Android with the NDK
# and copies it into apps/android's jniLibs.
#   ANDROID_NDK_HOME=/path/to/ndk sh scripts/android_lib.sh [aarch64|x86_64 ...]
set -eu
NDK=${ANDROID_NDK_HOME:-/opt/android-sdk/ndk/27.3.13750724}
API=26
TOOL="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
export ANDROID_NDK_ROOT="$NDK" PATH="$TOOL:$PATH" CARGO_PROFILE_RELEASE_DEBUG=0
for arch in ${*:-aarch64 x86_64}; do
  case $arch in
    aarch64) target=aarch64-linux-android; abi=arm64-v8a ;;
    x86_64) target=x86_64-linux-android; abi=x86_64 ;;
    *) echo "unknown arch $arch"; exit 2 ;;
  esac
  t=$(echo "$target" | tr a-z- A-Z_)
  envt=$(echo "$target" | tr - _)
  export "CC_$envt=$TOOL/$target$API-clang" "CXX_$envt=$TOOL/$target$API-clang++" "AR_$envt=$TOOL/llvm-ar" \
    "RANLIB_$envt=$TOOL/llvm-ranlib" "CARGO_TARGET_${t}_LINKER=$TOOL/$target$API-clang"
  cargo build -q --release -p tree-ffi --lib --target "$target"
  mkdir -p "apps/android/app/src/main/jniLibs/$abi"
  cp "target/$target/release/libtree_ffi.so" "apps/android/app/src/main/jniLibs/$abi/"
  "$TOOL/llvm-strip" "apps/android/app/src/main/jniLibs/$abi/libtree_ffi.so"
  ls -la "apps/android/app/src/main/jniLibs/$abi/libtree_ffi.so"
done

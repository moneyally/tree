#!/bin/sh
# Generates the app bindings (Kotlin for Android and desktop, Swift for iOS)
# from the built library into bindings/generated (not committed).
#   sh scripts/gen_bindings.sh
set -eu
BIN=${BIN:-target/debug}
cargo build -q -p tree-ffi
for lang in kotlin swift python; do
  "$BIN/uniffi-bindgen" generate --library "$BIN/libtree_ffi.so" --language "$lang" \
    --out-dir "bindings/generated/$lang" >/dev/null 2>&1
done
ls -R bindings/generated | grep -E "\.(kt|swift|py|h|modulemap)$"

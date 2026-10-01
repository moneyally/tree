#!/bin/sh
# Generates the Kotlin bindings and runs bindings/kotlin-jvm on the JVM
# (JNA) against a local server. Needs a JDK 21 and Gradle.
#   sh scripts/ffi_kotlin_demo.sh
set -eu
ROOT=$(pwd)
BIN=${BIN:-target/debug}
cargo build -q -p tree-server -p tree-ffi
DIR=$(mktemp -d)
PORT=${PORT:-18190}
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$DIR"' EXIT
"$BIN/uniffi-bindgen" generate --library "$BIN/libtree_ffi.so" --language kotlin --out-dir "$DIR/kt" >/dev/null 2>&1
DATABASE_URL="sqlite://$DIR/server.db" BIND_ADDR="127.0.0.1:$PORT" POW_BITS=12 RUST_LOG=warn \
  ATTACHMENT_DIR="$DIR/att" "$BIN/tree-server" &
SERVER=$!
sleep 1
cd bindings/kotlin-jvm
TREE_KT_BINDINGS="$DIR/kt" TREE_LIB_DIR="$ROOT/$BIN" TREE_URL="http://127.0.0.1:$PORT" \
  gradle -q --no-daemon run

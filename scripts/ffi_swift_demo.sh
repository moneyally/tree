#!/bin/sh
# Generates the Swift bindings, compiles bindings/swift/main.swift against
# the Rust library and runs it against a local server. Needs swiftc (Swift 6;
# on Linux e.g. /opt/swift/usr/bin).
#   sh scripts/ffi_swift_demo.sh
set -eu
BIN=${BIN:-target/debug}
SWIFTC=${SWIFTC:-swiftc}
export CARGO_PROFILE_DEV_DEBUG=0
cargo build -q -p tree-server -p tree-ffi
DIR=$(mktemp -d)
PORT=${PORT:-18210}
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$DIR"' EXIT
"$BIN/uniffi-bindgen" generate --library "$BIN/libtree_ffi.so" --language swift --out-dir "$DIR/gen" >/dev/null 2>&1
mv "$DIR/gen/tree_ffiFFI.modulemap" "$DIR/gen/module.modulemap"
"$SWIFTC" -O -I "$DIR/gen" -L "$BIN" -ltree_ffi "$DIR/gen/tree_ffi.swift" bindings/swift/main.swift -o "$DIR/demo"
DATABASE_URL="sqlite://$DIR/server.db" BIND_ADDR="127.0.0.1:$PORT" POW_BITS=12 RUST_LOG=warn \
  ATTACHMENT_DIR="$DIR/att" "$BIN/tree-server" &
SERVER=$!
sleep 1
TREE_URL="http://127.0.0.1:$PORT" LD_LIBRARY_PATH="$BIN" "$DIR/demo"

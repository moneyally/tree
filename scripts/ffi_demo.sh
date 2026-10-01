#!/bin/sh
# Builds the UniFFI library, generates Python bindings and runs
# bindings/python/ffi_demo.py against a local server.
#   sh scripts/ffi_demo.sh
set -eu
BIN=${BIN:-target/debug}
cargo build -q -p tree-server -p tree-ffi
DIR=$(mktemp -d)
PORT=${PORT:-18180}
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$DIR"' EXIT
"$BIN/uniffi-bindgen" generate --library "$BIN/libtree_ffi.so" --language python --out-dir "$DIR/py" >/dev/null 2>&1
cp "$BIN/libtree_ffi.so" "$DIR/py/"
DATABASE_URL="sqlite://$DIR/server.db" BIND_ADDR="127.0.0.1:$PORT" POW_BITS=12 RUST_LOG=warn \
  ATTACHMENT_DIR="$DIR/att" "$BIN/tree-server" &
SERVER=$!
sleep 1
TREE_PY_BINDINGS="$DIR/py" TREE_URL="http://127.0.0.1:$PORT" python3 bindings/python/ffi_demo.py

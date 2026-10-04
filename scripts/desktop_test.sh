#!/bin/sh
# Builds the desktop app and runs its model tests against a local server.
#   sh scripts/desktop_test.sh
set -eu
# Respects CARGO_TARGET_DIR (a shared build directory).
BIN=${BIN:-${CARGO_TARGET_DIR:-target}/debug}
export CARGO_PROFILE_DEV_DEBUG=0
cargo build -q -p tree-server -p tree-ffi
DIR=$(mktemp -d)
PORT=${PORT:-18200}
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$DIR"' EXIT
DATABASE_URL="sqlite://$DIR/server.db" BIND_ADDR="127.0.0.1:$PORT" POW_BITS=8 RUST_LOG=warn \
  ATTACHMENT_DIR="$DIR/att" "$BIN/tree-server" &
SERVER=$!
sleep 1
cd apps/desktop
TREE_URL="http://127.0.0.1:$PORT" gradle -q --no-daemon test
echo "desktop model tests passed"

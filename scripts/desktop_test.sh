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
# A one-run operator token (random, never stored): the model tests' accounts
# are all new, so the new-account limits (tested in tree-server) are
# released, as in the Rust tests.
TOKEN=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
TOKEN_SHA=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
# Every model test signs up its own accounts: more than the default per-IP burst.
ADMIN_TOKEN_SHA256="$TOKEN_SHA" DATABASE_URL="sqlite://$DIR/server.db" BIND_ADDR="127.0.0.1:$PORT" POW_BITS=8 RUST_LOG=warn SIGNUP_BURST=50 \
  ATTACHMENT_DIR="$DIR/att" "$BIN/tree-server" &
SERVER=$!
sleep 1
curl -fsS -X POST -H "X-Tree-Admin: $TOKEN" "http://127.0.0.1:$PORT/v1/features/server.new_account_limits/release" >/dev/null
cd apps/desktop
TREE_URL="http://127.0.0.1:$PORT" gradle -q --no-daemon test
echo "desktop model tests passed"

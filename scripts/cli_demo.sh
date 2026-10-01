#!/bin/sh
# Two people chat through a locally running Tree server, each with their own
# `tree` process and encrypted profile. Everything goes over HTTP.
#   sh scripts/cli_demo.sh            (after: cargo build -p tree-server -p tree-cli)
set -eu
BIN=${BIN:-target/debug}
DIR=$(mktemp -d)
PORT=${PORT:-18080}
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$DIR"' EXIT

DATABASE_URL="sqlite://$DIR/server.db" BIND_ADDR="127.0.0.1:$PORT" POW_BITS=12 RUST_LOG=warn \
  "$BIN/tree-server" &
SERVER=$!
sleep 1
URL="http://127.0.0.1:$PORT"

alice() { TREE_PASSPHRASE="alice pass" "$BIN/tree" --profile "$DIR/alice.db" "$@"; }
bob()   { TREE_PASSPHRASE="bob pass"   "$BIN/tree" --profile "$DIR/bob.db" "$@"; }
step()  { printf '\n== %s\n' "$*"; }

step "alice and bob create profiles and accounts (no phone number)"
alice init alice "$URL" 12
bob init bob "$URL" 12
bob username bob_tree
BOB_ACCOUNT=$(alice find @bob_tree)
BOB_MEMBER=$(bob whoami | awk '/^member/ {print $2}')

step "alice starts a group and invites bob's account"
G=$(alice create-group)
alice invite "$G" "$BOB_ACCOUNT"

step "bob syncs: alice is a stranger to him, so her chat arrives as a request"
bob sync
bob requests
bob accept "$G"

step "chat"
alice send "$G" "안녕 밥, 서버를 거쳐서 왔어"
bob sync
bob send "$G" "잘 받았어, 앨리스"
alice sync

step "bob reports a message; the server checks it really came from alice (franking)"
SPAM=$(alice send "$G" "spam spam spam" | awk '{print $3}')
bob sync
bob report "$G" spam "$SPAM" | tee "$DIR/report.txt"
grep -q "(verified)" "$DIR/report.txt"

step "both compare the safety number (the same 60 digits on both sides)"
alice safety "$BOB_ACCOUNT"
ALICE_ACCOUNT=$(alice whoami | awk '/^account/ {print $2}')
bob safety "$ALICE_ACCOUNT"
alice verify "$BOB_ACCOUNT"

step "members as alice sees them"
alice members "$G"

step "bob refreshes his keys; alice removes bob afterwards"
bob refresh "$G"
alice sync
alice remove "$G" "$BOB_MEMBER"
bob sync
alice send "$G" "밥은 이제 못 읽어"
bob sync

step "what the server database holds (searching for the plaintext; only the reported message is there)"
if grep -a -q -e "서버를 거쳐서" -e "alice" -e "bob_tree" "$DIR"/server.db* 2>/dev/null; then
  echo "!!! plaintext or name found on the server"; exit 1
else
  echo "no plaintext, no names in the server database"
fi

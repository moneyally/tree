#!/bin/sh
# Runs every ProVerif model in this directory, prints the RESULT lines and
# compares them with expected_results.txt. Exit code 0 only if they match.
# Usage: formal/run.sh            (PROVERIF=/path/to/proverif to override)
set -u
cd "$(dirname "$0")"
PV="${PROVERIF:-proverif}"
"$PV" -help >/dev/null 2>&1 || { echo "proverif not found (set PROVERIF=...)"; exit 2; }
out=$(for f in *.pv; do
  echo "== $f"
  timeout 600 "$PV" "$f" 2>&1 | grep -E "^RESULT|Error|error:" || echo "   (no result: timeout or error)"
done)
echo "$out"
if [ "$out" = "$(cat expected_results.txt)" ]; then
  echo "all results as expected"
else
  echo "RESULTS DIFFER from expected_results.txt"
  exit 1
fi

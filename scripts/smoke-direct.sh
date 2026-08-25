#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill "$AGENT_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP/bin"
go build -o "$TMP/bin/wd" "$ROOT/cmd/wd"
go build -o "$TMP/bin/wd-agent" "$ROOT/cmd/wd-agent"

INIT=$($TMP/bin/wd-agent init --state "$TMP/agent" --name smoke-agent)
FP=$(printf '%s\n' "$INIT" | awk -F'  +' '/Fingerprint:/ {print $2}')
SECRET=$(printf '%s\n' "$INIT" | awk -F'  +' '/Pair secret:/ {print $2}')
$TMP/bin/wd-agent serve --state "$TMP/agent" --name smoke-agent --listen 127.0.0.1:17443 --shell /bin/sh >"$TMP/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1
WEDECENT_PAIRING_SECRET=$SECRET $TMP/bin/wd pair --state "$TMP/client" --name smoke-client --endpoint 127.0.0.1:17443 --fingerprint "$FP"
DEVICE=$($TMP/bin/wd devices --state "$TMP/client" | cut -f1)
set +e
printf 'printf "WEDECENT_SMOKE_OK\\n"\nexit 17\n' | $TMP/bin/wd connect --state "$TMP/client" "$DEVICE" >"$TMP/out"
STATUS=$?
set -e
cat "$TMP/out"
[ "$STATUS" -eq 17 ]
grep -q WEDECENT_SMOKE_OK "$TMP/out"
printf 'Smoke test passed.\n'

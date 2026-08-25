#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${RELAY_PID:-}" ]; then kill "$RELAY_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP/bin"
go build -o "$TMP/bin/wd" "$ROOT/cmd/wd"
go build -o "$TMP/bin/wd-agent" "$ROOT/cmd/wd-agent"
go build -o "$TMP/bin/wd-relay" "$ROOT/cmd/wd-relay"

sh "$ROOT/scripts/dev-relay-cert.sh" "$TMP/certs" >/dev/null 2>&1
"$TMP/bin/wd-relay" \
  --listen 127.0.0.1:18443 \
  --cert "$TMP/certs/relay.crt" \
  --key "$TMP/certs/relay.key" >"$TMP/relay.log" 2>&1 &
RELAY_PID=$!

INIT=$($TMP/bin/wd-agent init --state "$TMP/agent" --name relay-smoke-agent)
FP=$(printf '%s\n' "$INIT" | awk -F'  +' '/Fingerprint:/ {print $2}')
SECRET=$(printf '%s\n' "$INIT" | awk -F'  +' '/Pair secret:/ {print $2}')
DEVICE=$(printf '%s\n' "$INIT" | awk -F'  +' '/Device ID:/ {print $2}')

"$TMP/bin/wd-agent" serve \
  --state "$TMP/agent" \
  --name relay-smoke-agent \
  --listen '' \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --relay-slots 2 \
  --shell /bin/sh >"$TMP/agent.log" 2>&1 &
AGENT_PID=$!

# Allow the outbound relay slots to register.
sleep 1

WEDECENT_PAIRING_SECRET=$SECRET "$TMP/bin/wd" pair \
  --state "$TMP/client" \
  --name relay-smoke-client \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --device-id "$DEVICE" \
  --fingerprint "$FP"

set +e
printf 'printf "WEDECENT_RELAY_OK\\n"\nexit 23\n' | "$TMP/bin/wd" connect \
  --state "$TMP/client" \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  "$DEVICE" >"$TMP/out"
STATUS=$?
set -e

cat "$TMP/out"
[ "$STATUS" -eq 23 ]
grep -q WEDECENT_RELAY_OK "$TMP/out"
printf 'Relay smoke test passed.\n'

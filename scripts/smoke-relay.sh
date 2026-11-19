#!/usr/bin/env sh
set -eu
unset WEDECENT_PAIRING_SECRET || true

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
umask 077
cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${RELAY_PID:-}" ]; then kill "$RELAY_PID" 2>/dev/null || true; fi
  if [ -n "${AUTH_PID:-}" ]; then kill "$AUTH_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP/bin"
go build -o "$TMP/bin/wd" "$ROOT/cmd/wd"
go build -o "$TMP/bin/wd-agent" "$ROOT/cmd/wd-agent"
go build -o "$TMP/bin/wd-relay" "$ROOT/cmd/wd-relay"
go build -o "$TMP/bin/auth-server" "$ROOT/scripts/smoke-auth-server.go"

"$TMP/bin/auth-server" --listen 127.0.0.1:18444 >"$TMP/auth.log" 2>&1 &
AUTH_PID=$!
sleep 1
kill -0 "$AUTH_PID"

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
printf '%s\n' "$SECRET" >"$TMP/pairing.secret"
chmod 600 "$TMP/pairing.secret"
unset SECRET INIT

"$TMP/bin/wd-agent" serve \
  --state "$TMP/agent" \
  --name relay-smoke-agent \
  --listen '' \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --relay-slots 2 \
  --authorization-url http://127.0.0.1:18444 \
  --shell /bin/sh >"$TMP/agent.log" 2>&1 &
AGENT_PID=$!

# Allow the outbound relay slots to register.
sleep 1

"$TMP/bin/wd" pair \
  --state "$TMP/client" \
  --name relay-smoke-client \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --device-id "$DEVICE" \
  --fingerprint "$FP" \
  --pairing-secret-file "$TMP/pairing.secret"

GRANT_JTI=76b4c468-4e39-437c-a9c8-b758c92ab89b
GRANT_ID=d90987bf-bae6-45da-ab21-c82d049617bd
GRANT_PAYLOAD=$(printf '{"jti":"%s","grant_id":"%s"}' "$GRANT_JTI" "$GRANT_ID" | base64 | tr -d '\n=' | tr '+/' '-_')
printf 'header.%s.signature\n' "$GRANT_PAYLOAD" >"$TMP/grant.jwt"
chmod 600 "$TMP/grant.jwt"
set +e
printf 'printf "WEDECENT_RELAY_OK\\n"\nexit 23\n' | "$TMP/bin/wd" connect \
  --state "$TMP/client" \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --connection-grant-file "$TMP/grant.jwt" \
  "$DEVICE" >"$TMP/out"
STATUS=$?
set -e

cat "$TMP/out"
[ "$STATUS" -eq 23 ]
grep -q WEDECENT_RELAY_OK "$TMP/out"
printf 'Relay smoke test passed.\n'

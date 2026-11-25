#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
cleanup() {
  result=$?
  trap - EXIT INT TERM
  if [ "$result" -ne 0 ]; then
    for log in "$TMP/agent.log" "$TMP/relay.log" "$TMP/auth.log" "$TMP/recovery-authority.log"; do
      if [ -f "$log" ]; then
        printf '\n--- %s ---\n' "$log" >&2
        cat "$log" >&2
      fi
    done
  fi
  if [ -n "${AGENT_PID:-}" ]; then kill "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${RELAY_PID:-}" ]; then kill "$RELAY_PID" 2>/dev/null || true; fi
  if [ -n "${AUTHORITY_PID:-}" ]; then kill "$AUTHORITY_PID" 2>/dev/null || true; fi
  if [ -n "${AUTH_PID:-}" ]; then kill "$AUTH_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
  exit "$result"
}
trap cleanup EXIT INT TERM

wait_for_log() {
  file=$1
  pattern=$2
  pid=$3
  attempts=0
  while ! grep -q "$pattern" "$file" 2>/dev/null; do
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$file" >&2 2>/dev/null || true
      return 1
    fi
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 100 ]; then
      cat "$file" >&2 2>/dev/null || true
      return 1
    fi
    sleep 0.1
  done
}

mkdir -p "$TMP/bin"
go build -o "$TMP/bin/wd" "$ROOT/cmd/wd"
go build -o "$TMP/bin/wd-agent" "$ROOT/cmd/wd-agent"
go build -o "$TMP/bin/wd-relay" "$ROOT/cmd/wd-relay"
go build -o "$TMP/bin/auth-server" "$ROOT/scripts/smoke-auth-server.go"
go build -o "$TMP/bin/recovery-authority" "$ROOT/cmd/wd-smoke-recovery-authority"

"$TMP/bin/auth-server" --listen 127.0.0.1:18444 >"$TMP/auth.log" 2>&1 &
AUTH_PID=$!
sleep 1
kill -0 "$AUTH_PID"

"$TMP/bin/recovery-authority" --listen 127.0.0.1:18445 --trust-file "$TMP/recovery-trust.json" --ca-file "$TMP/recovery-ca.pem" --pin-file "$TMP/recovery-pin.txt" --token smoke-token >"$TMP/recovery-authority.log" 2>&1 &
AUTHORITY_PID=$!
wait_for_log "$TMP/recovery-authority.log" "test recovery authority listening" "$AUTHORITY_PID"
RECOVERY_PIN=$(cat "$TMP/recovery-pin.txt")

sh "$ROOT/scripts/dev-relay-cert.sh" "$TMP/certs" >/dev/null 2>&1
"$TMP/bin/wd-relay" \
  --listen 127.0.0.1:18443 \
  --cert "$TMP/certs/relay.crt" \
  --key "$TMP/certs/relay.key" >"$TMP/relay.log" 2>&1 &
RELAY_PID=$!
wait_for_log "$TMP/relay.log" "WeDecent relay listening" "$RELAY_PID"

INIT=$($TMP/bin/wd-agent init --state "$TMP/agent" --name relay-smoke-agent)
FP=$(printf '%s\n' "$INIT" | awk -F'  +' '/Fingerprint:/ {print $2}')
SECRET=$(printf '%s\n' "$INIT" | awk -F'  +' '/Pair secret:/ {print $2}')
DEVICE=$(printf '%s\n' "$INIT" | awk -F'  +' '/Device ID:/ {print $2}')

WEDECENT_PAIRING_RECOVERY_AUTHORITY_TOKEN=smoke-token SSL_CERT_FILE="$TMP/recovery-ca.pem" "$TMP/bin/wd-agent" serve \
  --pairing-recovery-authority-url=https://127.0.0.1:18445 \
  --pairing-recovery-authority-spki-sha256="$RECOVERY_PIN" \
  --pairing-recovery-trust="$TMP/recovery-trust.json" \
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

# Wait until both outbound slots are parked before attempting a client connection.
attempts=0
while [ "$(grep -c 'relay slot parked' "$TMP/agent.log" 2>/dev/null || true)" -lt 2 ]; do
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    cat "$TMP/agent.log" >&2
    exit 1
  fi
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 100 ]; then
    printf 'agent did not park both relay slots\n' >&2
    cat "$TMP/agent.log" >&2
    exit 1
  fi
  sleep 0.1
done

WEDECENT_PAIRING_SECRET=$SECRET "$TMP/bin/wd" pair \
  --state "$TMP/client" \
  --name relay-smoke-client \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --device-id "$DEVICE" \
  --fingerprint "$FP"

printf '%s\n' 'header.payload.signature' >"$TMP/grant.jwt"
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

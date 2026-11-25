#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${AUTH_PID:-}" ]; then kill "$AUTH_PID" 2>/dev/null || true; fi
  if [ -n "${AUTHORITY_PID:-}" ]; then kill "$AUTHORITY_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP/bin"
go build -o "$TMP/bin/wd" "$ROOT/cmd/wd"
go build -o "$TMP/bin/wd-agent" "$ROOT/cmd/wd-agent"
go build -o "$TMP/bin/auth-server" "$ROOT/scripts/smoke-auth-server.go"
go build -o "$TMP/bin/recovery-authority" "$ROOT/cmd/wd-smoke-recovery-authority"

"$TMP/bin/auth-server" --listen 127.0.0.1:17444 >"$TMP/auth.log" 2>&1 &
AUTH_PID=$!
sleep 1
kill -0 "$AUTH_PID"

"$TMP/bin/recovery-authority" --listen 127.0.0.1:17445 --trust-file "$TMP/recovery-trust.json" --ca-file "$TMP/recovery-ca.pem" --pin-file "$TMP/recovery-pin.txt" --token smoke-token >"$TMP/recovery-authority.log" 2>&1 &
AUTHORITY_PID=$!
sleep 1
kill -0 "$AUTHORITY_PID"
RECOVERY_PIN=$(cat "$TMP/recovery-pin.txt")

INIT=$($TMP/bin/wd-agent init --state "$TMP/agent" --name smoke-agent)
FP=$(printf '%s\n' "$INIT" | awk -F'  +' '/Fingerprint:/ {print $2}')
SECRET=$(printf '%s\n' "$INIT" | awk -F'  +' '/Pair secret:/ {print $2}')
WEDECENT_PAIRING_RECOVERY_AUTHORITY_TOKEN=smoke-token SSL_CERT_FILE="$TMP/recovery-ca.pem" $TMP/bin/wd-agent serve --state "$TMP/agent" --name smoke-agent --listen 127.0.0.1:17443 --authorization-url http://127.0.0.1:17444 --pairing-recovery-authority-url=https://127.0.0.1:17445 --pairing-recovery-authority-spki-sha256="$RECOVERY_PIN" --pairing-recovery-trust="$TMP/recovery-trust.json" --shell /bin/sh >"$TMP/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1
WEDECENT_PAIRING_SECRET=$SECRET $TMP/bin/wd pair --state "$TMP/client" --name smoke-client --endpoint 127.0.0.1:17443 --fingerprint "$FP"
DEVICE=$($TMP/bin/wd devices --state "$TMP/client" | cut -f1)
printf '%s\n' 'header.payload.signature' >"$TMP/grant.jwt"
set +e
printf 'printf "WEDECENT_SMOKE_OK\\n"\nexit 17\n' | $TMP/bin/wd connect --state "$TMP/client" --connection-grant-file "$TMP/grant.jwt" "$DEVICE" >"$TMP/out"
STATUS=$?
set -e
cat "$TMP/out"
[ "$STATUS" -eq 17 ]
grep -q WEDECENT_SMOKE_OK "$TMP/out"
printf 'Smoke test passed.\n'

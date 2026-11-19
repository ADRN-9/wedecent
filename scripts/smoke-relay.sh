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
go build -tags wedecent_smoke_test -o "$TMP/bin/wd-agent" "$ROOT/cmd/wd-agent"
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

AGENT_SHA256=$(sha256sum "$TMP/bin/wd-agent" | awk '{print $1}')
EXPECTED_AGENT_COMMIT=unknown
EXPECTED_AGENT_SOURCE_SHA256=unknown

write_grant() {
  grant_file="$1"
  jti="$2"
  grant_id="$3"
  payload=$(printf '{"jti":"%s","grant_id":"%s"}' "$jti" "$grant_id" | base64 | tr -d '\n=' | tr '+/' '-_')
  printf 'header.%s.signature\n' "$payload" >"$grant_file"
  chmod 600 "$grant_file"
}

write_grant "$TMP/grant-first.jwt" 76b4c468-4e39-437c-a9c8-b758c92ab89b d90987bf-bae6-45da-ab21-c82d049617bd
write_grant "$TMP/grant-mismatch.jwt" 86b4c468-4e39-437c-a9c8-b758c92ab89b e90987bf-bae6-45da-ab21-c82d049617bd
write_grant "$TMP/grant-reconnect.jwt" 96b4c468-4e39-437c-a9c8-b758c92ab89b f90987bf-bae6-45da-ab21-c82d049617bd

set +e
printf 'printf "WEDECENT_RELAY_OK\\n"\nexit 23\n' | "$TMP/bin/wd" connect \
  --state "$TMP/client" \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --connection-grant-file "$TMP/grant-first.jwt" \
  --expected-agent-commit "$EXPECTED_AGENT_COMMIT" \
  --expected-agent-source-sha256 "$EXPECTED_AGENT_SOURCE_SHA256" \
  --expected-agent-executable-sha256 "$AGENT_SHA256" \
  "$DEVICE" >"$TMP/first.out" 2>"$TMP/first.err"
STATUS=$?
set -e
cat "$TMP/first.out"
if [ "$STATUS" -ne 23 ]; then
  cat "$TMP/first.err" >&2
  echo "raw relay did not admit the valid first-session grant" >&2
  exit 1
fi
grep -q WEDECENT_RELAY_OK "$TMP/first.out"

set +e
printf 'printf "WEDECENT_RELAY_REPLAY_SHOULD_NOT_RUN\\n"\nexit 99\n' | "$TMP/bin/wd" connect \
  --state "$TMP/client" \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --connection-grant-file "$TMP/grant-first.jwt" \
  "$DEVICE" >"$TMP/replay.out" 2>"$TMP/replay.err"
REPLAY_STATUS=$?
set -e
if [ "$REPLAY_STATUS" -eq 0 ]; then
  echo "raw relay accepted a replayed connection grant" >&2
  exit 1
fi
grep -q "authorization_denied" "$TMP/replay.err"
if grep -q WEDECENT_RELAY_REPLAY_SHOULD_NOT_RUN "$TMP/replay.out"; then
  echo "raw relay executed terminal input for a replayed grant" >&2
  exit 1
fi

WRONG_AGENT_SHA256=$(printf '%064d' 0)
set +e
printf 'exit 0\n' | "$TMP/bin/wd" connect \
  --state "$TMP/client" \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --connection-grant-file "$TMP/grant-mismatch.jwt" \
  --expected-agent-commit "$EXPECTED_AGENT_COMMIT" \
  --expected-agent-source-sha256 "$EXPECTED_AGENT_SOURCE_SHA256" \
  --expected-agent-executable-sha256 "$WRONG_AGENT_SHA256" \
  "$DEVICE" >"$TMP/mismatch.out" 2>"$TMP/mismatch.err"
MISMATCH_STATUS=$?
set -e
if [ "$MISMATCH_STATUS" -eq 0 ]; then
  echo "client accepted a mismatched target-agent executable SHA-256 attestation" >&2
  exit 1
fi
grep -q "target agent build identity does not match the expected source commit" "$TMP/mismatch.err"

set +e
printf 'printf "WEDECENT_RELAY_RECONNECT_OK\\n"\nexit 24\n' | "$TMP/bin/wd" connect \
  --state "$TMP/client" \
  --relay 127.0.0.1:18443 \
  --relay-ca "$TMP/certs/ca.crt" \
  --relay-server-name localhost \
  --connection-grant-file "$TMP/grant-reconnect.jwt" \
  --expected-agent-commit "$EXPECTED_AGENT_COMMIT" \
  --expected-agent-source-sha256 "$EXPECTED_AGENT_SOURCE_SHA256" \
  --expected-agent-executable-sha256 "$AGENT_SHA256" \
  "$DEVICE" >"$TMP/reconnect.out" 2>"$TMP/reconnect.err"
RECONNECT_STATUS=$?
set -e
cat "$TMP/reconnect.out"
if [ "$RECONNECT_STATUS" -ne 24 ]; then
  cat "$TMP/reconnect.err" >&2
  echo "raw relay reconnect with a fresh grant failed" >&2
  exit 1
fi
grep -q WEDECENT_RELAY_RECONNECT_OK "$TMP/reconnect.out"

printf 'Raw relay authorization, replay, fresh-grant reconnect, and executable-attestation smoke tests passed.\n'

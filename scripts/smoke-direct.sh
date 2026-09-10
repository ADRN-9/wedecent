#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${AUTH_PID:-}" ]; then kill "$AUTH_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP/bin"
go build -o "$TMP/bin/wd" "$ROOT/cmd/wd"
go build -o "$TMP/bin/wd-agent" "$ROOT/cmd/wd-agent"

cat >"$TMP/auth.go" <<'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/time", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `{"unix_ms":%d}`, time.Now().UnixMilli())
	})
	mux.HandleFunc("/v1/direct-authorize/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "missing authorization proof", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-WeDecent-Connection-Grant") != "header.payload.signature" {
			http.Error(w, "unexpected connection grant", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(strings.TrimPrefix(r.URL.Path, "/v1/direct-authorize/"), "wd_") {
			http.Error(w, "invalid target", http.StatusBadRequest)
			return
		}
		var body struct {
			ClientDeviceID string `json:"client_device_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !strings.HasPrefix(body.ClientDeviceID, "wd_") {
			http.Error(w, "invalid client", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:17444", mux))
}
EOF

go build -o "$TMP/bin/auth-server" "$TMP/auth.go"
"$TMP/bin/auth-server" >"$TMP/auth.log" 2>&1 &
AUTH_PID=$!
sleep 1
kill -0 "$AUTH_PID"

INIT=$($TMP/bin/wd-agent init --state "$TMP/agent" --name smoke-agent)
FP=$(printf '%s\n' "$INIT" | awk -F'  +' '/Fingerprint:/ {print $2}')
SECRET=$(printf '%s\n' "$INIT" | awk -F'  +' '/Pair secret:/ {print $2}')
$TMP/bin/wd-agent serve --state "$TMP/agent" --name smoke-agent --listen 127.0.0.1:17443 --authorization-url http://127.0.0.1:17444 --shell /bin/sh >"$TMP/agent.log" 2>&1 &
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

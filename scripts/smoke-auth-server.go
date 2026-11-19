package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	deviceIDPattern = regexp.MustCompile("^wd_[a-z2-7]{16}$")
	uuidPattern = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
	evidenceByGrant sync.Map
)

type grantClaims struct {
	JTI string `json:"jti"`
	GrantID string `json:"grant_id"`
}

type grantEvidence struct {
	Version int `json:"version"`
	GrantID string `json:"grant_id"`
	JTI string `json:"jti"`
	ClientDeviceID string `json:"client_device_id"`
	TargetDeviceID string `json:"target_device_id"`
	Permission string `json:"permission"`
	Flow string `json:"flow"`
	ValidationOutcome string `json:"validation_outcome"`
	ConsumptionOutcome string `json:"consumption_outcome"`
	ValidatedAt string `json:"validated_at"`
	ConsumedAt string `json:"consumed_at"`
	ExpiresAt string `json:"expires_at"`
	RetainUntilMS int64 `json:"retain_until_ms"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:17444", "loopback listen address")
	flag.Parse()

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
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer wdt2.") {
			http.Error(w, "invalid authorization proof", http.StatusUnauthorized)
			return
		}
		target := strings.TrimPrefix(r.URL.Path, "/v1/direct-authorize/")
		if !deviceIDPattern.MatchString(target) {
			http.Error(w, "invalid target", http.StatusBadRequest)
			return
		}
		var body struct {
			ClientDeviceID string `json:"client_device_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !deviceIDPattern.MatchString(body.ClientDeviceID) || body.ClientDeviceID == target {
			http.Error(w, "invalid client", http.StatusBadRequest)
			return
		}
		parts := strings.Split(r.Header.Get("X-WeDecent-Connection-Grant"), ".")
		if len(parts) != 3 {
			http.Error(w, "invalid connection grant", http.StatusForbidden)
			return
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			http.Error(w, "invalid connection grant payload", http.StatusForbidden)
			return
		}
		var claims grantClaims
		if err := json.Unmarshal(payload, &claims); err != nil || !uuidPattern.MatchString(claims.JTI) || !uuidPattern.MatchString(claims.GrantID) {
			http.Error(w, "invalid connection grant claims", http.StatusForbidden)
			return
		}
		now := time.Now().UTC()
		evidence := grantEvidence{
			Version: 1, GrantID: strings.ToLower(claims.GrantID), JTI: strings.ToLower(claims.JTI),
			ClientDeviceID: body.ClientDeviceID, TargetDeviceID: target,
			Permission: "terminal.connect", Flow: "direct",
			ValidationOutcome: "accepted", ConsumptionOutcome: "consumed",
			ValidatedAt: now.Format(time.RFC3339Nano), ConsumedAt: now.Format(time.RFC3339Nano),
			ExpiresAt: now.Add(90 * time.Second).Format(time.RFC3339Nano),
			RetainUntilMS: now.Add(7 * 24 * time.Hour).UnixMilli(),
		}
		key := target + "/" + evidence.JTI
		if _, loaded := evidenceByGrant.LoadOrStore(key, evidence); loaded {
			http.Error(w, "connection grant already used", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/relay-authorize/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer wdt2.") {
			http.Error(w, "invalid authorization proof", http.StatusUnauthorized)
			return
		}
		target := strings.TrimPrefix(r.URL.Path, "/v1/relay-authorize/")
		if !deviceIDPattern.MatchString(target) {
			http.Error(w, "invalid target", http.StatusBadRequest)
			return
		}
		var body struct {
			ClientDeviceID string `json:"client_device_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !deviceIDPattern.MatchString(body.ClientDeviceID) || body.ClientDeviceID == target {
			http.Error(w, "invalid client", http.StatusBadRequest)
			return
		}
		parts := strings.Split(r.Header.Get("X-WeDecent-Connection-Grant"), ".")
		if len(parts) != 3 {
			http.Error(w, "invalid connection grant", http.StatusForbidden)
			return
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			http.Error(w, "invalid connection grant payload", http.StatusForbidden)
			return
		}
		var claims grantClaims
		if err := json.Unmarshal(payload, &claims); err != nil || !uuidPattern.MatchString(claims.JTI) || !uuidPattern.MatchString(claims.GrantID) {
			http.Error(w, "invalid connection grant claims", http.StatusForbidden)
			return
		}
		now := time.Now().UTC()
		evidence := grantEvidence{
			Version: 1, GrantID: strings.ToLower(claims.GrantID), JTI: strings.ToLower(claims.JTI),
			ClientDeviceID: body.ClientDeviceID, TargetDeviceID: target,
			Permission: "terminal.connect", Flow: "relay",
			ValidationOutcome: "accepted", ConsumptionOutcome: "consumed",
			ValidatedAt: now.Format(time.RFC3339Nano), ConsumedAt: now.Format(time.RFC3339Nano),
			ExpiresAt: now.Add(90 * time.Second).Format(time.RFC3339Nano),
			RetainUntilMS: now.Add(7 * 24 * time.Hour).UnixMilli(),
		}
		key := target + "/" + evidence.JTI
		if _, loaded := evidenceByGrant.LoadOrStore(key, evidence); loaded {
			http.Error(w, "connection grant already used", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/grant-evidence/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer wdt2.") {
			http.Error(w, "invalid authorization proof", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/grant-evidence/"), "/")
		if len(parts) != 2 || !deviceIDPattern.MatchString(parts[0]) || !uuidPattern.MatchString(parts[1]) {
			http.Error(w, "invalid evidence path", http.StatusBadRequest)
			return
		}
		value, ok := evidenceByGrant.Load(parts[0] + "/" + strings.ToLower(parts[1]))
		if !ok {
			http.Error(w, "grant evidence not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(value)
	})
	log.Fatal(http.ListenAndServe(*listen, mux))
}

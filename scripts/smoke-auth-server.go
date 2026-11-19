package main

import (
	"crypto/rand"
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
	uuidPattern     = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

	evidenceMu   sync.RWMutex
	evidenceByGrant = make(map[string]grantEvidence)
	eventsByID      = make(map[string]grantEventEvidence)
)

type grantClaims struct {
	JTI     string `json:"jti"`
	GrantID string `json:"grant_id"`
}

type grantEventEvidence struct {
	EventID        string `json:"event_id"`
	RunID          string `json:"run_id"`
	AttemptID      string `json:"attempt_id"`
	Type           string `json:"type"`
	Outcome        string `json:"outcome"`
	GrantID        string `json:"grant_id"`
	JTI            string `json:"jti"`
	ClientDeviceID string `json:"client_device_id"`
	TargetDeviceID string `json:"target_device_id"`
	Permission     string `json:"permission"`
	Flow           string `json:"flow"`
	OccurredAt     string `json:"occurred_at"`
	RetainUntilMS  int64  `json:"retain_until_ms"`
}

type grantEvidence struct {
	Version              int                `json:"version"`
	AuthorizationRunID   string             `json:"authorization_run_id"`
	ValidationAttemptID  string             `json:"validation_attempt_id"`
	ConsumptionAttemptID string             `json:"consumption_attempt_id"`
	ValidationEventID    string             `json:"validation_event_id"`
	ConsumptionEventID   string             `json:"consumption_event_id"`
	ValidationEvent      grantEventEvidence `json:"validation_event"`
	ConsumptionEvent     grantEventEvidence `json:"consumption_event"`
	GrantID              string             `json:"grant_id"`
	JTI                  string             `json:"jti"`
	ClientDeviceID       string             `json:"client_device_id"`
	TargetDeviceID       string             `json:"target_device_id"`
	Permission           string             `json:"permission"`
	Flow                 string             `json:"flow"`
	ValidationOutcome    string             `json:"validation_outcome"`
	ConsumptionOutcome   string             `json:"consumption_outcome"`
	ValidatedAt          string             `json:"validated_at"`
	ConsumedAt           string             `json:"consumed_at"`
	ExpiresAt            string             `json:"expires_at"`
	RetainUntilMS        int64              `json:"retain_until_ms"`
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func newGrantEvidence(claims grantClaims, clientID, target, flow string, now time.Time) (
	grantEvidence, grantEventEvidence, grantEventEvidence, error,
) {
	ids := make([]string, 5)
	seen := make(map[string]struct{}, len(ids))
	for index := range ids {
		for {
			id, err := newUUID()
			if err != nil {
				return grantEvidence{}, grantEventEvidence{}, grantEventEvidence{}, err
			}
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			ids[index] = id
			break
		}
	}

	validatedAt := now.UTC().Format(time.RFC3339Nano)
	consumedAt := now.UTC().Format(time.RFC3339Nano)
	retainUntil := now.Add(7 * 24 * time.Hour).UnixMilli()
	grantID := strings.ToLower(claims.GrantID)
	jti := strings.ToLower(claims.JTI)

	validationEvent := grantEventEvidence{
		EventID: ids[3], RunID: ids[0], AttemptID: ids[1],
		Type: "authorization.validation", Outcome: "accepted",
		GrantID: grantID, JTI: jti, ClientDeviceID: clientID, TargetDeviceID: target,
		Permission: "terminal.connect", Flow: flow, OccurredAt: validatedAt, RetainUntilMS: retainUntil,
	}
	consumptionEvent := grantEventEvidence{
		EventID: ids[4], RunID: ids[0], AttemptID: ids[2],
		Type: "authorization.consumption", Outcome: "consumed",
		GrantID: grantID, JTI: jti, ClientDeviceID: clientID, TargetDeviceID: target,
		Permission: "terminal.connect", Flow: flow, OccurredAt: consumedAt, RetainUntilMS: retainUntil,
	}
	evidence := grantEvidence{
		Version: 1, AuthorizationRunID: ids[0], ValidationAttemptID: ids[1],
		ConsumptionAttemptID: ids[2], ValidationEventID: ids[3], ConsumptionEventID: ids[4],
		GrantID: grantID, JTI: jti, ClientDeviceID: clientID, TargetDeviceID: target,
		Permission: "terminal.connect", Flow: flow,
		ValidationOutcome: "accepted", ConsumptionOutcome: "consumed",
		ValidatedAt: validatedAt, ConsumedAt: consumedAt,
		ExpiresAt: now.Add(90 * time.Second).UTC().Format(time.RFC3339Nano),
		RetainUntilMS: retainUntil,
	}
	return evidence, validationEvent, consumptionEvent, nil
}

func storeGrantEvidence(
	key string,
	evidence grantEvidence,
	validationEvent, consumptionEvent grantEventEvidence,
) bool {
	evidenceMu.Lock()
	defer evidenceMu.Unlock()
	if _, exists := evidenceByGrant[key]; exists {
		return false
	}
	eventsByID[validationEvent.EventID] = validationEvent
	eventsByID[consumptionEvent.EventID] = consumptionEvent
	evidenceByGrant[key] = evidence
	return true
}

func loadGrantEvidence(key string) (grantEvidence, grantEventEvidence, grantEventEvidence, bool) {
	evidenceMu.RLock()
	defer evidenceMu.RUnlock()
	evidence, exists := evidenceByGrant[key]
	if !exists {
		return grantEvidence{}, grantEventEvidence{}, grantEventEvidence{}, false
	}
	validationEvent, validationExists := eventsByID[evidence.ValidationEventID]
	consumptionEvent, consumptionExists := eventsByID[evidence.ConsumptionEventID]
	if !validationExists || !consumptionExists {
		return grantEvidence{}, grantEventEvidence{}, grantEventEvidence{}, false
	}
	return evidence, validationEvent, consumptionEvent, true
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
	mux.HandleFunc("/v1/direct-authorize/", authorizationHandler("direct"))
	mux.HandleFunc("/v1/relay-authorize/", authorizationHandler("relay"))
	mux.HandleFunc("/v1/grant-evidence/", grantEvidenceHandler())
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func authorizationHandler(flow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer wdt2.") {
			http.Error(w, "invalid authorization proof", http.StatusUnauthorized)
			return
		}
		target := strings.TrimPrefix(r.URL.Path, "/v1/"+flow+"-authorize/")
		if !deviceIDPattern.MatchString(target) {
			http.Error(w, "invalid target", http.StatusBadRequest)
			return
		}
		var body struct {
			ClientDeviceID string `json:"client_device_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
			!deviceIDPattern.MatchString(body.ClientDeviceID) || body.ClientDeviceID == target {
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
		if err := json.Unmarshal(payload, &claims); err != nil ||
			!uuidPattern.MatchString(claims.JTI) || !uuidPattern.MatchString(claims.GrantID) {
			http.Error(w, "invalid connection grant claims", http.StatusForbidden)
			return
		}
		evidence, validationEvent, consumptionEvent, err := newGrantEvidence(claims, body.ClientDeviceID, target, flow, time.Now())
		if err != nil {
			http.Error(w, "could not create authorization evidence", http.StatusInternalServerError)
			return
		}
		key := target + "/" + evidence.JTI
		if !storeGrantEvidence(key, evidence, validationEvent, consumptionEvent) {
			http.Error(w, "connection grant already used", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func grantEvidenceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		evidence, validationEvent, consumptionEvent, ok := loadGrantEvidence(parts[0] + "/" + strings.ToLower(parts[1]))
		if !ok {
			http.Error(w, "grant evidence not found", http.StatusNotFound)
			return
		}
		evidence.ValidationEvent = validationEvent
		evidence.ConsumptionEvent = consumptionEvent
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(evidence)
	}
}

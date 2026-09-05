package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/enrollment"
	"wedecent.com/wedecent/internal/identity"
)

func TestRunAccountEnrollSignsServerChallenge(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "client")
	id, err := identity.Ensure(stateDir, "DESKTOP-TEST")
	if err != nil {
		t.Fatal(err)
	}

	const (
		userID      = "11111111-1111-4111-8111-111111111111"
		orgID       = "22222222-2222-4222-8222-222222222222"
		challengeID = "33333333-3333-4333-8333-333333333333"
	)
	challenge := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	expiresUnixMS := time.Now().Add(5 * time.Minute).UnixMilli()
	var calls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/functions/v1/device-enrollment" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get("apikey") != "publishable-test" {
			t.Fatalf("unexpected auth headers")
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		publicKey, _ := body["public_key"].(string)
		if body["device_id"] != id.ID || publicKey != base64.RawURLEncoding.EncodeToString(id.PublicKey) || body["kind"] != "client" || body["name"] != id.Name || body["organization_id"] != orgID {
			t.Fatalf("unexpected enrollment body: %#v", body)
		}

		switch body["action"] {
		case "challenge":
			writeHTTPJSON(t, w, map[string]any{
				"action":          "challenge",
				"challenge_id":    challengeID,
				"challenge":       challenge,
				"user_id":         userID,
				"device_id":       id.ID,
				"public_key":      publicKey,
				"kind":            "client",
				"name":            id.Name,
				"organization_id": orgID,
				"expires_unix_ms": expiresUnixMS,
			})
		case "complete":
			signatureText, _ := body["signature"].(string)
			signature, err := base64.RawURLEncoding.DecodeString(signatureText)
			if err != nil {
				t.Fatal(err)
			}
			message, err := enrollment.Message(enrollment.ProofFields{
				ChallengeID:    challengeID,
				Challenge:      challenge,
				UserID:         userID,
				DeviceID:       id.ID,
				PublicKey:      publicKey,
				Kind:           "client",
				OrganizationID: orgID,
				ExpiresUnixMS:  expiresUnixMS,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(id.PublicKey, message, signature) {
				t.Fatal("client enrollment signature did not verify")
			}
			writeHTTPJSON(t, w, map[string]any{
				"action": "complete",
				"device": map[string]any{
					"device_id":       id.ID,
					"public_key":      publicKey,
					"kind":            "client",
					"name":            id.Name,
					"owner_user_id":   userID,
					"organization_id": orgID,
				},
			})
		default:
			http.Error(w, "unexpected action", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	session := &account.Session{
		Version:        account.SessionVersion,
		SupabaseURL:    server.URL,
		PublishableKey: "publishable-test",
		UserID:         userID,
		Email:          "admin@example.com",
		AccessToken:    "access",
		RefreshToken:   "refresh",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}
	if err := account.Save(account.SessionPath(stateDir), session); err != nil {
		t.Fatal(err)
	}

	if err := runAccountEnroll([]string{"--state", stateDir, "--name", "DESKTOP-TEST", "--organization-id", orgID}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("enrollment calls = %d", calls.Load())
	}

	// Ensure the local identity remains stable after enrollment.
	again, err := identity.Ensure(stateDir, "DESKTOP-TEST")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != id.ID {
		t.Fatalf("identity changed after enrollment: got %s want %s", again.ID, id.ID)
	}
}

func writeHTTPJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}

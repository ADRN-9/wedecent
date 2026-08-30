package account

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientDeviceEnrollmentRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	userID := "11111111-1111-4111-8111-111111111111"
	orgID := "22222222-2222-4222-8222-222222222222"
	challengeID := "33333333-3333-4333-8333-333333333333"
	deviceID := "wd_aaaaaaaaaaaaaaaa"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	challenge := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	expiresUnixMS := now.Add(5 * time.Minute).UnixMilli()
	calls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/functions/v1/device-enrollment" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("apikey"); got != "publishable-test" {
			t.Fatalf("apikey = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access" {
			t.Fatalf("authorization = %q", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["device_id"] != deviceID || body["public_key"] != publicKey || body["kind"] != "client" || body["name"] != "DESKTOP-TEST" || body["organization_id"] != orgID {
			t.Fatalf("unexpected common enrollment body: %#v", body)
		}

		switch body["action"] {
		case "challenge":
			writeJSON(t, w, map[string]any{
				"action":          "challenge",
				"challenge_id":    challengeID,
				"challenge":       challenge,
				"user_id":         userID,
				"device_id":       deviceID,
				"public_key":      publicKey,
				"kind":            "client",
				"name":            "DESKTOP-TEST",
				"organization_id": orgID,
				"expires_unix_ms": expiresUnixMS,
			})
		case "complete":
			if body["challenge_id"] != challengeID || body["challenge"] != challenge || body["signature"] != signature {
				t.Fatalf("unexpected proof body: %#v", body)
			}
			writeJSON(t, w, map[string]any{
				"action": "complete",
				"device": map[string]any{
					"device_id":       deviceID,
					"public_key":      publicKey,
					"kind":            "client",
					"name":            "DESKTOP-TEST",
					"owner_user_id":   userID,
					"organization_id": orgID,
				},
			})
		default:
			http.Error(w, "unexpected action", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	session := validSession(server.URL, now.Add(time.Hour).Unix())
	session.UserID = userID
	client := Client{HTTP: server.Client(), Now: func() time.Time { return now }}

	gotChallenge, err := client.RequestClientEnrollmentChallenge(context.Background(), session, deviceID, publicKey, "DESKTOP-TEST", orgID)
	if err != nil {
		t.Fatal(err)
	}
	if gotChallenge.ChallengeID != challengeID || gotChallenge.UserID != userID || gotChallenge.ExpiresUnixMS != expiresUnixMS {
		t.Fatalf("challenge = %#v", gotChallenge)
	}

	device, err := client.CompleteClientEnrollment(context.Background(), session, DeviceEnrollmentProof{
		ChallengeID:    gotChallenge.ChallengeID,
		Challenge:      gotChallenge.Challenge,
		DeviceID:       deviceID,
		PublicKey:      publicKey,
		Kind:           "client",
		Name:           "DESKTOP-TEST",
		OrganizationID: orgID,
		ExpiresUnixMS:  gotChallenge.ExpiresUnixMS,
		Signature:      signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	if device.DeviceID != deviceID || device.OwnerUserID != userID || device.OrganizationID != orgID {
		t.Fatalf("device = %#v", device)
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestClientEnrollmentChallengeRejectsMismatchedContext(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"action":          "challenge",
			"challenge_id":    "33333333-3333-4333-8333-333333333333",
			"challenge":       challenge,
			"user_id":         "11111111-1111-4111-8111-111111111111",
			"device_id":       "wd_bbbbbbbbbbbbbbbb",
			"public_key":      publicKey,
			"kind":            "client",
			"name":            "DESKTOP-TEST",
			"organization_id": nil,
			"expires_unix_ms": now.Add(5 * time.Minute).UnixMilli(),
		})
	}))
	defer server.Close()

	session := validSession(server.URL, now.Add(time.Hour).Unix())
	session.UserID = "11111111-1111-4111-8111-111111111111"
	client := Client{HTTP: server.Client(), Now: func() time.Time { return now }}
	_, err := client.RequestClientEnrollmentChallenge(context.Background(), session, "wd_aaaaaaaaaaaaaaaa", publicKey, "DESKTOP-TEST", "")
	if err == nil || !strings.Contains(err.Error(), "mismatched device challenge") {
		t.Fatalf("error = %v", err)
	}
}

func TestClientEnrollmentChallengeRejectsInvalidExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"action":          "challenge",
			"challenge_id":    "33333333-3333-4333-8333-333333333333",
			"challenge":       challenge,
			"user_id":         "11111111-1111-4111-8111-111111111111",
			"device_id":       "wd_aaaaaaaaaaaaaaaa",
			"public_key":      publicKey,
			"kind":            "client",
			"name":            "DESKTOP-TEST",
			"organization_id": nil,
			"expires_unix_ms": 0,
		})
	}))
	defer server.Close()

	session := validSession(server.URL, now.Add(time.Hour).Unix())
	session.UserID = "11111111-1111-4111-8111-111111111111"
	client := Client{HTTP: server.Client(), Now: func() time.Time { return now }}
	_, err := client.RequestClientEnrollmentChallenge(context.Background(), session, "wd_aaaaaaaaaaaaaaaa", publicKey, "DESKTOP-TEST", "")
	if err == nil || !strings.Contains(err.Error(), "invalid challenge expiry") {
		t.Fatalf("error = %v", err)
	}
}

func TestCompleteClientEnrollmentRejectsMismatchedDevice(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"action": "complete",
			"device": map[string]any{
				"device_id":     "wd_bbbbbbbbbbbbbbbb",
				"public_key":    publicKey,
				"kind":          "client",
				"owner_user_id": "11111111-1111-4111-8111-111111111111",
			},
		})
	}))
	defer server.Close()

	session := validSession(server.URL, now.Add(time.Hour).Unix())
	session.UserID = "11111111-1111-4111-8111-111111111111"
	client := Client{HTTP: server.Client(), Now: func() time.Time { return now }}
	_, err := client.CompleteClientEnrollment(context.Background(), session, DeviceEnrollmentProof{
		ChallengeID:   "33333333-3333-4333-8333-333333333333",
		Challenge:     challenge,
		DeviceID:      "wd_aaaaaaaaaaaaaaaa",
		PublicKey:     publicKey,
		Kind:          "client",
		Name:          "DESKTOP-TEST",
		ExpiresUnixMS: now.Add(5 * time.Minute).UnixMilli(),
		Signature:     signature,
	})
	if err == nil || !strings.Contains(err.Error(), "mismatched device identity") {
		t.Fatalf("error = %v", err)
	}
}

func TestAgentDeviceEnrollmentRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	userID := "11111111-1111-4111-8111-111111111111"
	orgID := "22222222-2222-4222-8222-222222222222"
	challengeID := "33333333-3333-4333-8333-333333333333"
	deviceID := "wd_aaaaaaaaaaaaaaaa"
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	challenge := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	expiresUnixMS := now.Add(5 * time.Minute).UnixMilli()
	calls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["device_id"] != deviceID || body["public_key"] != publicKey || body["kind"] != "agent" || body["name"] != "WEDECENT-RC3-TEST" || body["organization_id"] != orgID {
			t.Fatalf("unexpected agent enrollment body: %#v", body)
		}
		switch body["action"] {
		case "challenge":
			writeJSON(t, w, map[string]any{
				"action":          "challenge",
				"challenge_id":    challengeID,
				"challenge":       challenge,
				"user_id":         userID,
				"device_id":       deviceID,
				"public_key":      publicKey,
				"kind":            "agent",
				"name":            "WEDECENT-RC3-TEST",
				"organization_id": orgID,
				"expires_unix_ms": expiresUnixMS,
			})
		case "complete":
			if body["challenge_id"] != challengeID || body["challenge"] != challenge || body["signature"] != signature {
				t.Fatalf("unexpected agent proof body: %#v", body)
			}
			writeJSON(t, w, map[string]any{
				"action": "complete",
				"device": map[string]any{
					"device_id":       deviceID,
					"public_key":      publicKey,
					"kind":            "agent",
					"name":            "WEDECENT-RC3-TEST",
					"owner_user_id":   userID,
					"organization_id": orgID,
				},
			})
		default:
			http.Error(w, "unexpected action", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	session := validSession(server.URL, now.Add(time.Hour).Unix())
	session.UserID = userID
	client := Client{HTTP: server.Client(), Now: func() time.Time { return now }}

	gotChallenge, err := client.RequestDeviceEnrollmentChallenge(context.Background(), session, DeviceEnrollmentRequest{
		Action:         "challenge",
		DeviceID:       deviceID,
		PublicKey:      publicKey,
		Kind:           "agent",
		Name:           "WEDECENT-RC3-TEST",
		OrganizationID: orgID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotChallenge.Kind != "agent" || gotChallenge.ChallengeID != challengeID {
		t.Fatalf("challenge = %#v", gotChallenge)
	}

	device, err := client.CompleteDeviceEnrollment(context.Background(), session, DeviceEnrollmentProof{
		ChallengeID:    gotChallenge.ChallengeID,
		Challenge:      gotChallenge.Challenge,
		DeviceID:       deviceID,
		PublicKey:      publicKey,
		Kind:           "agent",
		Name:           "WEDECENT-RC3-TEST",
		OrganizationID: orgID,
		ExpiresUnixMS:  gotChallenge.ExpiresUnixMS,
		Signature:      signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	if device.DeviceID != deviceID || device.Kind != "agent" || device.OwnerUserID != userID {
		t.Fatalf("device = %#v", device)
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}

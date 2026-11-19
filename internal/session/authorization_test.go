package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
)

func TestRelayDirectAuthorizerUsesDedicatedHeadersAndBody(t *testing.T) {
	id, err := identity.Ensure(t.TempDir(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	clientDeviceID := "wd_aaaaaaaaaaaaaaaa"
	grant := "header.payload.signature"
	var sawAuthorize bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/time":
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]any{"unix_ms": time.Now().UnixMilli()})
		case "/v1/direct-authorize/" + id.ID:
			sawAuthorize = true
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if strings.Contains(r.URL.String(), grant) {
				t.Fatal("connection grant leaked into URL")
			}
			if got := r.Header.Get(connectionGrantHeader); got != grant {
				t.Fatalf("connection grant header = %q", got)
			}
			if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer wdt2.") {
				t.Fatalf("authorization header = %q", got)
			}
			var body struct {
				ClientDeviceID string `json:"client_device_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.ClientDeviceID != clientDeviceID {
				t.Fatalf("client_device_id = %q", body.ClientDeviceID)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	a := RelayDirectAuthorizer{BaseURL: server.URL, Identity: id, HTTP: server.Client(), allowLoopbackForTests: true}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Authorize(ctx, clientDeviceID, id.ID, grant); err != nil {
		t.Fatal(err)
	}
	if !sawAuthorize {
		t.Fatal("direct authorization endpoint was not called")
	}
}

func TestRelayDirectAuthorizerRejectsRedirect(t *testing.T) {
	id, err := identity.Ensure(t.TempDir(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/time" {
			_ = json.NewEncoder(w).Encode(map[string]any{"unix_ms": time.Now().UnixMilli()})
			return
		}
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	a := RelayDirectAuthorizer{BaseURL: server.URL, Identity: id, allowLoopbackForTests: true}
	err = a.Authorize(context.Background(), "wd_aaaaaaaaaaaaaaaa", id.ID, "header.payload.signature")
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("error = %v", err)
	}
}

func TestDirectAuthorizationURLRequiresExactProductionOrigin(t *testing.T) {
	got, err := directAuthorizationURL("https://relay.wedecent.com", "wd_aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://relay.wedecent.com/v1/direct-authorize/wd_aaaaaaaaaaaaaaaa" {
		t.Fatalf("got %q", got)
	}

	for _, rejected := range []string{
		"http://relay.example",
		"https://relay.example",
		"https://relay.wedecent.com.evil.example",
		"https://relay.wedecent.com:8443",
		"wss://relay.wedecent.com",
		"http://127.0.0.1:17444",
		"http://localhost:17444",
		"https://user@relay.wedecent.com",
		"https://relay.wedecent.com/path",
		"https://relay.wedecent.com?redirect=evil",
	} {
		if _, err := directAuthorizationURL(rejected, "wd_aaaaaaaaaaaaaaaa"); err == nil {
			t.Fatalf("accepted unapproved authorization origin %q", rejected)
		}
	}
}

func TestRelayDirectAuthorizerRejectsLoopbackOutsideTestMode(t *testing.T) {
	id, err := identity.Ensure(t.TempDir(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	a := RelayDirectAuthorizer{
		BaseURL:  "http://127.0.0.1:17444",
		Identity: id,
		TicketSource: func(context.Context, string, string, string, int) (string, error) {
			called = true
			return "wdt2.test-ticket.signature", nil
		},
	}
	if err := a.Authorize(context.Background(), "wd_aaaaaaaaaaaaaaaa", id.ID, "header.payload.signature"); err == nil {
		t.Fatal("accepted loopback authorization origin without test-only opt-in")
	}
	if called {
		t.Fatal("requested an authorization ticket before validating the origin")
	}
	if err := a.VerifyConsumption(context.Background(), "wd_aaaaaaaaaaaaaaaa", id.ID, "76b4c468-4e39-437c-a9c8-b758c92ab89b", "direct"); err == nil {
		t.Fatal("accepted loopback evidence origin without test-only opt-in")
	}
}

func TestRelayDirectAuthorizerVerifiesIndependentGrantEvidence(t *testing.T) {
	id, err := identity.Ensure(t.TempDir(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	clientID := "wd_aaaaaaaaaaaaaaaa"
	jti := "76b4c468-4e39-437c-a9c8-b758c92ab89b"
	flow := "direct"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/grant-evidence/"+id.ID+"/"+jti {
			t.Fatalf("unexpected evidence request: %s %s", r.Method, r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer wdt2.") {
			t.Fatal("evidence request is missing its target authorization ticket")
		}
		_ = json.NewEncoder(w).Encode(GrantConsumptionEvidence{
			Version: 1, GrantID: "d90987bf-bae6-45da-ab21-c82d049617bd", JTI: jti,
			ClientDeviceID: clientID, TargetDeviceID: id.ID, Permission: "terminal.connect", Flow: flow,
			ValidationOutcome: "accepted", ConsumptionOutcome: "consumed",
			ValidatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
			ConsumedAt:    time.Now().UTC().Format(time.RFC3339Nano),
			ExpiresAt:     time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
			RetainUntilMS: time.Now().Add(time.Hour).UnixMilli(),
		})
	}))
	defer server.Close()

	a := RelayDirectAuthorizer{
		BaseURL:               server.URL,
		Identity:              id,
		allowLoopbackForTests: true,
		TicketSource: func(_ context.Context, baseURL, targetDeviceID, role string, slot int) (string, error) {
			if baseURL != server.URL || targetDeviceID != id.ID || role != "authorize" || slot != 0 {
				t.Fatalf("unexpected ticket source request: %q %q %q %d", baseURL, targetDeviceID, role, slot)
			}
			return "wdt2.target-ticket.signature", nil
		},
		HTTP: server.Client(),
	}
	if err := a.VerifyConsumption(context.Background(), clientID, id.ID, jti, "direct"); err != nil {
		t.Fatal(err)
	}
	flow = "relay"
	if err := a.VerifyConsumption(context.Background(), clientID, id.ID, jti, "relay"); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyConsumption(context.Background(), "wd_bbbbbbbbbbbbbbbb", id.ID, jti, "relay"); err == nil {
		t.Fatal("accepted evidence for a different client identity")
	}
	if err := a.VerifyConsumption(context.Background(), clientID, id.ID, jti, "direct"); err == nil {
		t.Fatal("accepted evidence for a different session flow")
	}
}

func TestConnectionGrantJTIRequiresStructuredPayload(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"76b4c468-4e39-437c-a9c8-b758c92ab89b"}`))
	got, err := ConnectionGrantJTI("eyJhbGciOiJFZERTQSJ9." + payload + ".signature")
	if err != nil || got != "76b4c468-4e39-437c-a9c8-b758c92ab89b" {
		t.Fatalf("ConnectionGrantJTI = %q, %v", got, err)
	}
	if _, err := ConnectionGrantJTI("header.payload.signature"); err == nil {
		t.Fatal("accepted malformed connection grant payload")
	}
}

func TestAuthorizeTicketSourceRole(t *testing.T) {
	id, err := identity.Ensure(t.TempDir(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	a := RelayDirectAuthorizer{
		BaseURL:  productionAuthorizationOrigin,
		Identity: id,
		TicketSource: func(_ context.Context, baseURL, targetDeviceID, role string, slot int) (string, error) {
			called = true
			if baseURL != productionAuthorizationOrigin || targetDeviceID != id.ID || role != "authorize" || slot != 0 {
				t.Fatalf("unexpected ticket request: %q %q %q %d", baseURL, targetDeviceID, role, slot)
			}
			return "wdt2.payload.signature", nil
		},
		HTTP: &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       http.NoBody,
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})},
	}
	if err := a.Authorize(context.Background(), "wd_aaaaaaaaaaaaaaaa", id.ID, "header.payload.signature"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("ticket source was not called")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

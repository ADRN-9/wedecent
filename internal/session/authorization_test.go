package session

import (
	"context"
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

	a := RelayDirectAuthorizer{BaseURL: server.URL, Identity: id, HTTP: server.Client()}
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

	a := RelayDirectAuthorizer{BaseURL: server.URL, Identity: id}
	err = a.Authorize(context.Background(), "wd_aaaaaaaaaaaaaaaa", id.ID, "header.payload.signature")
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("error = %v", err)
	}
}

func TestDirectAuthorizationURLRejectsRemotePlaintext(t *testing.T) {
	_, err := directAuthorizationURL("http://relay.example", "wd_aaaaaaaaaaaaaaaa")
	if err == nil || !strings.Contains(err.Error(), "requires HTTPS") {
		t.Fatalf("error = %v", err)
	}
}

func TestDirectAuthorizationURLConvertsWebSocketScheme(t *testing.T) {
	got, err := directAuthorizationURL("wss://relay.wedecent.com/v1/stream/ignored?x=1", "wd_aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://relay.wedecent.com/v1/direct-authorize/wd_aaaaaaaaaaaaaaaa" {
		t.Fatalf("got %q", got)
	}
}

func TestAuthorizeTicketSourceRole(t *testing.T) {
	id, err := identity.Ensure(t.TempDir(), "agent")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	a := RelayDirectAuthorizer{
		BaseURL:  "https://relay.example",
		Identity: id,
		TicketSource: func(_ context.Context, baseURL, targetDeviceID, role string, slot int) (string, error) {
			called = true
			if baseURL != "https://relay.example" || targetDeviceID != id.ID || role != "authorize" || slot != 0 {
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

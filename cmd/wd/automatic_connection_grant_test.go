package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
)

func TestAutomaticConnectionGrant(t *testing.T) {
	now := time.Now()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/functions/v1/connection-grant" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access" {
			t.Fatalf("authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant": "header.payload.signature",
			"claims": map[string]any{
				"client_device_id": "wd_aaaaaaaaaaaaaaaa",
				"target_device_id": "wd_bbbbbbbbbbbbbbbb",
				"permission":       "terminal.connect",
			},
		})
	}))
	defer server.Close()

	stateDir := filepath.Join(t.TempDir(), "client")
	if err := account.Save(account.SessionPath(stateDir), &account.Session{
		Version: account.SessionVersion, SupabaseURL: server.URL, PublishableKey: "publishable-test",
		UserID: "user-1", Email: "admin@example.com", AccessToken: "access", RefreshToken: "refresh", ExpiresAt: now.Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	grant, err := automaticConnectionGrant(context.Background(), stateDir, "wd_aaaaaaaaaaaaaaaa", "wd_bbbbbbbbbbbbbbbb", account.Client{HTTP: server.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if grant != "header.payload.signature" {
		t.Fatalf("grant = %q", grant)
	}
}

func TestAutomaticConnectionGrantRequiresLogin(t *testing.T) {
	_, err := automaticConnectionGrant(context.Background(), t.TempDir(), "wd_aaaaaaaaaaaaaaaa", "wd_bbbbbbbbbbbbbbbb", account.Client{})
	if err == nil || !strings.Contains(err.Error(), "wd account login") {
		t.Fatalf("error = %v", err)
	}
}

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/identity"
)

func TestPrepareRoutedDialerRejectsMissingTrustBeforeAuthorization(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "client")
	id, err := identity.Ensure(stateDir, "source")
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "must not be called", http.StatusInternalServerError)
	}))
	defer server.Close()

	now := time.Now()
	if err := account.Save(account.SessionPath(stateDir), &account.Session{
		Version:        account.SessionVersion,
		SupabaseURL:    server.URL,
		PublishableKey: "publishable-test",
		UserID:         "user-1",
		Email:          "user@example.com",
		AccessToken:    "access",
		RefreshToken:   "refresh",
		ExpiresAt:      now.Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	_, _, err = prepareRoutedDialer(
		context.Background(),
		stateDir,
		id,
		"wd_cccccccccccccccc",
		routedConnectConfig{
			RouterDeviceID:  "wd_bbbbbbbbbbbbbbbb",
			FirstTransport:  "lan",
			SecondTransport: "lan",
			FirstCost:       10,
			SecondCost:      20,
		},
		time.Second,
		account.Client{HTTP: server.Client(), Now: func() time.Time { return now }},
	)
	if err == nil || !strings.Contains(err.Error(), "not trusted for routing") {
		t.Fatalf("error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("authorization HTTP calls = %d, want 0", calls.Load())
	}
}

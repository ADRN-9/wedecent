package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/trust"
)

const (
	testRouteRouterID      = "wd_bbbbbbbbbbbbbbbb"
	testRouteDestinationID = "wd_cccccccccccccccc"
)

func prepareRoutedCLITestState(t *testing.T, serverURL string) string {
	t.Helper()

	stateDir := t.TempDir()

	store, err := trust.Open(filepath.Join(stateDir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(trust.Peer{
		ID:          testRouteDestinationID,
		Fingerprint: "test-fingerprint",
	}); err != nil {
		t.Fatal(err)
	}

	routeTrust, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := routeTrust.Put(trust.Peer{ID: testRouteRouterID}); err != nil {
		t.Fatal(err)
	}

	if err := account.Save(account.SessionPath(stateDir), &account.Session{
		Version:        account.SessionVersion,
		SupabaseURL:    serverURL,
		PublishableKey: "publishable-test",
		UserID:         "user-1",
		Email:          "user@example.com",
		AccessToken:    "access",
		RefreshToken:   "refresh",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	return stateDir
}

func writeTestConnectionGrant(t *testing.T, stateDir string) string {
	t.Helper()

	path := filepath.Join(stateDir, "connection-grant.jwt")
	if err := os.WriteFile(path, []byte("a.b.c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func routedCLIArgs(stateDir string) []string {
	return []string{
		"--state", stateDir,
		"--route-router", testRouteRouterID,
		"--route-first-transport", "lan",
		"--route-second-transport", "lan",
		testRouteDestinationID,
	}
}

func TestRunConnectRoutedConnectionGrantDenialPreventsRouteAuthorization(t *testing.T) {
	var totalCalls atomic.Int32
	var routeAuthorizationCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalCalls.Add(1)
		if strings.HasSuffix(r.URL.Path, "/route-authorization") {
			routeAuthorizationCalls.Add(1)
		}
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()

	stateDir := prepareRoutedCLITestState(t, server.URL)

	_, err := runConnect(routedCLIArgs(stateDir))
	if err == nil {
		t.Fatal("connection-grant denial was accepted")
	}
	if totalCalls.Load() != 1 {
		t.Fatalf("authorization HTTP calls = %d, want 1", totalCalls.Load())
	}
	if routeAuthorizationCalls.Load() != 0 {
		t.Fatalf("route authorization calls = %d, want 0", routeAuthorizationCalls.Load())
	}
}

func TestRunConnectRoutedRouteAuthorizationDenialStopsBeforeDial(t *testing.T) {
	var totalCalls atomic.Int32
	var routeAuthorizationCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalCalls.Add(1)
		if strings.HasSuffix(r.URL.Path, "/route-authorization") {
			routeAuthorizationCalls.Add(1)
		}
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()

	stateDir := prepareRoutedCLITestState(t, server.URL)
	grantPath := writeTestConnectionGrant(t, stateDir)

	args := routedCLIArgs(stateDir)
	args = append(args[:len(args)-1],
		"--connection-grant-file", grantPath,
		args[len(args)-1],
	)

	_, err := runConnect(args)
	if err == nil {
		t.Fatal("route-authorization denial was accepted")
	}
	if totalCalls.Load() != 1 {
		t.Fatalf("authorization HTTP calls = %d, want 1", totalCalls.Load())
	}
	if routeAuthorizationCalls.Load() != 1 {
		t.Fatalf("route authorization calls = %d, want 1", routeAuthorizationCalls.Load())
	}
}

func TestRunConnectRoutedInvalidTransportMakesNoAuthorizationRequest(t *testing.T) {
	var totalCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalCalls.Add(1)
		http.Error(w, "must not be called", http.StatusInternalServerError)
	}))
	defer server.Close()

	stateDir := prepareRoutedCLITestState(t, server.URL)
	grantPath := writeTestConnectionGrant(t, stateDir)

	args := []string{
		"--state", stateDir,
		"--connection-grant-file", grantPath,
		"--route-router", testRouteRouterID,
		"--route-first-transport", "bluetooth",
		"--route-second-transport", "lan",
		testRouteDestinationID,
	}

	_, err := runConnect(args)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "transport") {
		t.Fatalf("error = %v", err)
	}
	if totalCalls.Load() != 0 {
		t.Fatalf("authorization HTTP calls = %d, want 0", totalCalls.Load())
	}
}

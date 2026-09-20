package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/trust"
)

func TestRunConnectRoutedBypassesDestinationLocatorAndRequiresRouterTrust(t *testing.T) {
	stateDir := t.TempDir()
	destinationID := "wd_cccccccccccccccc"

	store, err := trust.Open(filepath.Join(stateDir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(trust.Peer{
		ID:          destinationID,
		Fingerprint: "test-fingerprint",
	}); err != nil {
		t.Fatal(err)
	}

	grantPath := filepath.Join(stateDir, "connection-grant.jwt")
	if err := os.WriteFile(grantPath, []byte("a.b.c\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = runConnect([]string{
		"--state", stateDir,
		"--lan-timeout", "0",
		"--connection-grant-file", grantPath,
		"--route-router", "wd_bbbbbbbbbbbbbbbb",
		"--route-first-transport", "lan",
		"--route-second-transport", "lan",
		destinationID,
	})
	if err == nil || !strings.Contains(err.Error(), "not trusted for routing") {
		t.Fatalf("error = %v", err)
	}
}

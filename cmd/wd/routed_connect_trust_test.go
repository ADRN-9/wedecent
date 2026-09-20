package main

import (
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/trust"
)

func TestOpenRoutedSourceRouterTrustDoesNotUseTerminalTrust(t *testing.T) {
	stateDir := t.TempDir()
	routerID := "wd_bbbbbbbbbbbbbbbb"

	terminalTrust, err := trust.Open(filepath.Join(stateDir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := terminalTrust.Put(trust.Peer{ID: routerID}); err != nil {
		t.Fatal(err)
	}

	if _, err := openRoutedSourceRouterTrust(stateDir, routerID); err == nil {
		t.Fatal("ordinary terminal trust granted routing trust")
	}
}

func TestOpenRoutedSourceRouterTrustAcceptsDedicatedTrust(t *testing.T) {
	stateDir := t.TempDir()
	routerID := "wd_bbbbbbbbbbbbbbbb"

	routeTrust, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := routeTrust.Put(trust.Peer{ID: routerID}); err != nil {
		t.Fatal(err)
	}

	store, err := openRoutedSourceRouterTrust(stateDir, routerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(routerID); !ok {
		t.Fatal("dedicated routing trust lost router")
	}
}

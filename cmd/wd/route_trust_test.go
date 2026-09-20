package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/trust"
)

const routeTrustTestRouterID = "wd_bbbbbbbbbbbbbbbb"

func routeTrustTestFingerprint() string {
	return "SHA256:" + strings.Repeat("A", 64)
}

func TestRouteTrustAddExplicitEndpointUsesDedicatedStore(t *testing.T) {
	stateDir := t.TempDir()

	peer, err := addRouteRouterTrust(
		context.Background(),
		stateDir,
		routeTrustTestRouterID,
		routeTrustTestFingerprint(),
		"127.0.0.1:7555",
		time.Second,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if peer.ID != routeTrustTestRouterID || peer.Endpoint != "tcp://127.0.0.1:7555" {
		t.Fatalf("unexpected route trust peer: %+v", peer)
	}

	routeStore, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := routeStore.Get(routeTrustTestRouterID); !ok {
		t.Fatal("router was not written to dedicated route trust")
	}

	terminalStore, err := trust.Open(filepath.Join(stateDir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := terminalStore.Get(routeTrustTestRouterID); ok {
		t.Fatal("route trust leaked into ordinary terminal trust")
	}
}

func TestRouteTrustAddViaSignedDiscovery(t *testing.T) {
	stateDir := t.TempDir()
	fp := routeTrustTestFingerprint()
	calls := 0
	finder := func(ctx context.Context, deviceID, fingerprint string) (discovery.Result, bool, error) {
		calls++
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
		if deviceID != routeTrustTestRouterID || fingerprint != fp {
			t.Fatalf("finder args = %q %q", deviceID, fingerprint)
		}
		return discovery.Result{
			DeviceID:    routeTrustTestRouterID,
			Name:        "router-b",
			Endpoint:    "10.0.0.20:7445",
			Fingerprint: fp,
		}, true, nil
	}

	peer, err := addRouteRouterTrust(
		context.Background(),
		stateDir,
		routeTrustTestRouterID,
		fp,
		"",
		time.Second,
		finder,
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("discovery calls = %d, want 1", calls)
	}
	if peer.Name != "router-b" || peer.Endpoint != "tcp://10.0.0.20:7445" {
		t.Fatalf("unexpected discovered route trust peer: %+v", peer)
	}
}

func TestRouteTrustRejectsDiscoveryIdentityMismatchWithoutMutation(t *testing.T) {
	stateDir := t.TempDir()
	finder := func(context.Context, string, string) (discovery.Result, bool, error) {
		return discovery.Result{
			DeviceID:    routeTrustTestRouterID,
			Endpoint:    "10.0.0.20:7445",
			Fingerprint: "SHA256:" + strings.Repeat("B", 64),
		}, true, nil
	}

	_, err := addRouteRouterTrust(
		context.Background(),
		stateDir,
		routeTrustTestRouterID,
		routeTrustTestFingerprint(),
		"",
		time.Second,
		finder,
	)
	if !errors.Is(err, discovery.ErrTrustedIdentityMismatch) {
		t.Fatalf("error = %v", err)
	}

	store, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(routeTrustTestRouterID); ok {
		t.Fatal("mismatched discovered router was persisted")
	}
}

func TestRouteTrustRejectsInvalidInputsWithoutMutation(t *testing.T) {
	stateDir := t.TempDir()

	if _, err := addRouteRouterTrust(
		context.Background(),
		stateDir,
		"wd_INVALID!!!!!!!!",
		routeTrustTestFingerprint(),
		"127.0.0.1:7555",
		time.Second,
		nil,
	); err == nil {
		t.Fatal("invalid router ID accepted")
	}

	if _, err := addRouteRouterTrust(
		context.Background(),
		stateDir,
		routeTrustTestRouterID,
		"not-a-fingerprint",
		"127.0.0.1:7555",
		time.Second,
		nil,
	); err == nil {
		t.Fatal("invalid fingerprint accepted")
	}

	if _, err := addRouteRouterTrust(
		context.Background(),
		stateDir,
		routeTrustTestRouterID,
		routeTrustTestFingerprint(),
		"not-an-endpoint",
		time.Second,
		nil,
	); err == nil {
		t.Fatal("invalid route-control endpoint accepted")
	}

	store, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.List()) != 0 {
		t.Fatalf("invalid inputs mutated route trust: %+v", store.List())
	}
}

func TestRouteTrustListSortedAndRevoke(t *testing.T) {
	stateDir := t.TempDir()
	store, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []trust.Peer{
		{ID: "wd_cccccccccccccccc", Fingerprint: routeTrustTestFingerprint(), Endpoint: "tcp://127.0.0.1:7556"},
		{ID: routeTrustTestRouterID, Fingerprint: routeTrustTestFingerprint(), Endpoint: "tcp://127.0.0.1:7555"},
	} {
		if err := store.Put(peer); err != nil {
			t.Fatal(err)
		}
	}

	peers, err := listRouteRouterTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 || peers[0].ID != routeTrustTestRouterID || peers[1].ID != "wd_cccccccccccccccc" {
		t.Fatalf("route trust list not sorted: %+v", peers)
	}

	removed, err := revokeRouteRouterTrust(stateDir, routeTrustTestRouterID)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("existing router was not revoked")
	}
	removed, err = revokeRouteRouterTrust(stateDir, routeTrustTestRouterID)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("second revoke unexpectedly reported removal")
	}
}

func TestRouteTrustCLIAddAndRevoke(t *testing.T) {
	stateDir := t.TempDir()
	fp := routeTrustTestFingerprint()

	if err := runRouteTrustAddWithFinder([]string{
		"--state", stateDir,
		"--fingerprint", fp,
		"--endpoint", "127.0.0.1:7555",
		routeTrustTestRouterID,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := runRouteTrustRevoke([]string{
		"--state", stateDir,
		routeTrustTestRouterID,
	}); err != nil {
		t.Fatal(err)
	}
}

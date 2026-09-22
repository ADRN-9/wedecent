package coreconnect

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/trust"
)

const (
	testRouteSourceID      = "wd_aaaaaaaaaaaaaaaa"
	testRouteDestinationID = "wd_bbbbbbbbbbbbbbbb"
	testRouteRouterOneID   = "wd_cccccccccccccccc"
	testRouteRouterTwoID   = "wd_dddddddddddddddd"
)

func writeRouteSelectionPolicy(t *testing.T, stateDir string, policy routeSelectionPolicy) {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, RouteSelectionPolicyFile), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func trustRouteRouter(t *testing.T, stateDir, routerID string) {
	t.Helper()
	store, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(trust.Peer{ID: routerID, Fingerprint: "unused-in-route-source-test", Endpoint: "tcp://127.0.0.1:7444"}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRouteSourceNoPolicyUsesExistingPath(t *testing.T) {
	source, err := NewPolicyRouteSource(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request, routed, err := source.RouteRequest(context.Background(), testRouteSourceID, testRouteDestinationID)
	if err != nil {
		t.Fatal(err)
	}
	if routed || request.RouterDeviceID != "" {
		t.Fatalf("request=%#v routed=%v", request, routed)
	}
}

func TestPolicyRouteSourceDisabledPolicyUsesExistingPath(t *testing.T) {
	stateDir := t.TempDir()
	writeRouteSelectionPolicy(t, stateDir, routeSelectionPolicy{
		Version:        routeSelectionPolicyVersion,
		Enabled:        false,
		SourceDeviceID: testRouteSourceID,
		Candidates: []RouteSelectionCandidate{{
			DestinationDeviceID: testRouteDestinationID,
			RouterDeviceID:      testRouteRouterOneID,
			FirstTransport:      mesh.TransportInternet,
			SecondTransport:     mesh.TransportInternet,
		}},
	})
	source, err := NewPolicyRouteSource(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	_, routed, err := source.RouteRequest(context.Background(), testRouteSourceID, testRouteDestinationID)
	if err != nil {
		t.Fatal(err)
	}
	if routed {
		t.Fatal("disabled route policy selected a route")
	}
}

func TestPolicyRouteSourceRequiresDedicatedSourceRouterTrust(t *testing.T) {
	stateDir := t.TempDir()
	writeRouteSelectionPolicy(t, stateDir, routeSelectionPolicy{
		Version:        routeSelectionPolicyVersion,
		Enabled:        true,
		SourceDeviceID: testRouteSourceID,
		Candidates: []RouteSelectionCandidate{{
			DestinationDeviceID: testRouteDestinationID,
			RouterDeviceID:      testRouteRouterOneID,
			FirstTransport:      mesh.TransportInternet,
			SecondTransport:     mesh.TransportInternet,
			FirstCost:           10,
			SecondCost:          20,
		}},
	})

	// Ordinary terminal trust must not imply the source->router routing role.
	terminalTrust, err := trust.Open(filepath.Join(stateDir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := terminalTrust.Put(trust.Peer{ID: testRouteRouterOneID, Fingerprint: "terminal-only"}); err != nil {
		t.Fatal(err)
	}

	source, err := NewPolicyRouteSource(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	_, routed, err := source.RouteRequest(context.Background(), testRouteSourceID, testRouteDestinationID)
	if err != nil {
		t.Fatal(err)
	}
	if routed {
		t.Fatal("terminal trust was incorrectly treated as routing trust")
	}

	trustRouteRouter(t, stateDir, testRouteRouterOneID)
	request, routed, err := source.RouteRequest(context.Background(), testRouteSourceID, testRouteDestinationID)
	if err != nil {
		t.Fatal(err)
	}
	if !routed || request.RouterDeviceID != testRouteRouterOneID {
		t.Fatalf("request=%#v routed=%v", request, routed)
	}
}

func TestPolicyRouteSourceSelectsLowestCostTrustedCandidate(t *testing.T) {
	stateDir := t.TempDir()
	writeRouteSelectionPolicy(t, stateDir, routeSelectionPolicy{
		Version:        routeSelectionPolicyVersion,
		Enabled:        true,
		SourceDeviceID: "  " + testRouteSourceID + "  ",
		Candidates: []RouteSelectionCandidate{
			{
				DestinationDeviceID: testRouteDestinationID,
				RouterDeviceID:      testRouteRouterOneID,
				FirstTransport:      mesh.TransportName(" INTERNET "),
				SecondTransport:     mesh.TransportName("LAN"),
				FirstCost:           30,
				SecondCost:          40,
			},
			{
				DestinationDeviceID: testRouteDestinationID,
				RouterDeviceID:      testRouteRouterTwoID,
				FirstTransport:      mesh.TransportLAN,
				SecondTransport:     mesh.TransportInternet,
				FirstCost:           10,
				SecondCost:          20,
			},
		},
	})
	trustRouteRouter(t, stateDir, testRouteRouterOneID)
	trustRouteRouter(t, stateDir, testRouteRouterTwoID)

	source, err := NewPolicyRouteSource(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	request, routed, err := source.RouteRequest(context.Background(), testRouteSourceID, testRouteDestinationID)
	if err != nil {
		t.Fatal(err)
	}
	if !routed {
		t.Fatal("expected routed candidate")
	}
	if request.SourceDeviceID != testRouteSourceID ||
		request.DestinationDeviceID != testRouteDestinationID ||
		request.RouterDeviceID != testRouteRouterTwoID ||
		request.FirstTransport != mesh.TransportLAN ||
		request.SecondTransport != mesh.TransportInternet ||
		request.FirstCost != 10 || request.SecondCost != 20 {
		t.Fatalf("request = %#v", request)
	}
}

func TestPolicyRouteSourceSkipsCheaperUntrustedRouter(t *testing.T) {
	stateDir := t.TempDir()
	writeRouteSelectionPolicy(t, stateDir, routeSelectionPolicy{
		Version:        routeSelectionPolicyVersion,
		Enabled:        true,
		SourceDeviceID: testRouteSourceID,
		Candidates: []RouteSelectionCandidate{
			{
				DestinationDeviceID: testRouteDestinationID,
				RouterDeviceID:      testRouteRouterOneID,
				FirstTransport:      mesh.TransportInternet,
				SecondTransport:     mesh.TransportInternet,
				FirstCost:           1,
				SecondCost:          1,
			},
			{
				DestinationDeviceID: testRouteDestinationID,
				RouterDeviceID:      testRouteRouterTwoID,
				FirstTransport:      mesh.TransportInternet,
				SecondTransport:     mesh.TransportInternet,
				FirstCost:           50,
				SecondCost:          50,
			},
		},
	})
	trustRouteRouter(t, stateDir, testRouteRouterTwoID)

	source, err := NewPolicyRouteSource(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	request, routed, err := source.RouteRequest(context.Background(), testRouteSourceID, testRouteDestinationID)
	if err != nil {
		t.Fatal(err)
	}
	if !routed || request.RouterDeviceID != testRouteRouterTwoID {
		t.Fatalf("request=%#v routed=%v", request, routed)
	}
}

func TestPolicyRouteSourceRejectsUnknownPolicyField(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, RouteSelectionPolicyFile)
	data := []byte(`{"version":1,"enabled":true,"source_device_id":"wd_aaaaaaaaaaaaaaaa","candidates":[],"unexpected":true}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewPolicyRouteSource(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := source.RouteRequest(context.Background(), testRouteSourceID, testRouteDestinationID); err == nil {
		t.Fatal("policy with unknown field unexpectedly accepted")
	}
}

func TestPolicyRouteSourceRejectsUnsupportedTransport(t *testing.T) {
	stateDir := t.TempDir()
	writeRouteSelectionPolicy(t, stateDir, routeSelectionPolicy{
		Version:        routeSelectionPolicyVersion,
		Enabled:        true,
		SourceDeviceID: testRouteSourceID,
		Candidates: []RouteSelectionCandidate{{
			DestinationDeviceID: testRouteDestinationID,
			RouterDeviceID:      testRouteRouterOneID,
			FirstTransport:      mesh.TransportBluetooth,
			SecondTransport:     mesh.TransportInternet,
		}},
	})
	source, err := NewPolicyRouteSource(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := source.RouteRequest(context.Background(), testRouteSourceID, testRouteDestinationID); err == nil {
		t.Fatal("unsupported route transport unexpectedly accepted")
	}
}

func TestPolicyRouteSourceRejectsMismatchedBoundSource(t *testing.T) {
	stateDir := t.TempDir()
	writeRouteSelectionPolicy(t, stateDir, routeSelectionPolicy{
		Version:        routeSelectionPolicyVersion,
		Enabled:        true,
		SourceDeviceID: testRouteRouterTwoID,
	})
	source, err := NewPolicyRouteSource(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := source.RouteRequest(context.Background(), testRouteSourceID, testRouteDestinationID); err == nil {
		t.Fatal("policy bound to another source unexpectedly accepted")
	}
}

func TestPolicyRouteSourceHonorsCanceledContext(t *testing.T) {
	source, err := NewPolicyRouteSource(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := source.RouteRequest(ctx, testRouteSourceID, testRouteDestinationID); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

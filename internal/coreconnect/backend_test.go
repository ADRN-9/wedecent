package coreconnect

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

type testHandle struct{ done chan struct{} }

func (h *testHandle) Close() error {
	select {
	case <-h.done:
	default:
		close(h.done)
	}
	return nil
}
func (h *testHandle) Done() <-chan struct{} { return h.done }

type fakeAuthorizer struct {
	mu            sync.Mutex
	grant         string
	route         mesh.Route
	authorization mesh.RouteAuthorization
	grantErr      error
	routeErr      error
	order         []string
	grantCalls    int
	routeCalls    int
}

func (a *fakeAuthorizer) IssueConnectionGrant(context.Context, string, string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.order = append(a.order, "grant")
	a.grantCalls++
	return a.grant, a.grantErr
}

func (a *fakeAuthorizer) IssueRouteAuthorization(context.Context, account.RouteAuthorizationRequest) (mesh.Route, mesh.RouteAuthorization, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.order = append(a.order, "route")
	a.routeCalls++
	return a.route, a.authorization, a.routeErr
}

type staticRouteSource struct {
	request account.RouteAuthorizationRequest
	enabled bool
	err     error
}

func (s staticRouteSource) RouteRequest(context.Context, string, string) (account.RouteAuthorizationRequest, bool, error) {
	return s.request, s.enabled, s.err
}

func testBackendTrust(t *testing.T, stateDir string, peers ...trust.Peer) *trust.Store {
	t.Helper()
	store, err := trust.Open(stateDir + "/trusted-devices.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if err := store.Put(peer); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func TestBackendOpensDirectPathWithConnectionGrant(t *testing.T) {
	stateDir := t.TempDir()
	id := &identity.Identity{ID: "wd_aaaaaaaaaaaaaaaa"}
	peer := trust.Peer{ID: "wd_bbbbbbbbbbbbbbbb", Fingerprint: "unused-in-test", Endpoint: "tcp://127.0.0.1:7443"}
	store := testBackendTrust(t, stateDir, peer)
	authorizer := &fakeAuthorizer{grant: "header.payload.signature"}
	var gotGrant string
	var gotPeer trust.Peer
	backend, err := New(Config{
		StateDir:   stateDir,
		Identity:   id,
		Trust:      store,
		Authorizer: authorizer,
		OpenTerminal: func(_ context.Context, _ *identity.Identity, _ *trust.Store, peer trust.Peer, _ transport.Dialer, grant string) (coreapi.ConnectionHandle, error) {
			gotPeer, gotGrant = peer, grant
			return &testHandle{done: make(chan struct{})}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	opened, err := backend.Open(context.Background(), peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Path != v1.ConnectionPathDirect || opened.Route != nil || opened.Handle == nil {
		t.Fatalf("opened = %#v", opened)
	}
	if gotPeer.Endpoint != peer.Endpoint || gotGrant != authorizer.grant || authorizer.grantCalls != 1 {
		t.Fatalf("peer=%#v grant=%q calls=%d", gotPeer, gotGrant, authorizer.grantCalls)
	}
}

func TestBackendWebRelayCarriesGrantInDialer(t *testing.T) {
	stateDir := t.TempDir()
	id := &identity.Identity{ID: "wd_aaaaaaaaaaaaaaaa"}
	peer := trust.Peer{ID: "wd_bbbbbbbbbbbbbbbb", Fingerprint: "unused-in-test", Endpoint: "wsrelay://relay.example/wd_bbbbbbbbbbbbbbbb"}
	store := testBackendTrust(t, stateDir, peer)
	authorizer := &fakeAuthorizer{grant: "header.payload.signature"}
	var gotDialer transport.Dialer
	backend, err := New(Config{
		StateDir:   stateDir,
		Identity:   id,
		Trust:      store,
		Authorizer: authorizer,
		FindTrusted: func(context.Context, string, string) (discovery.Result, bool, error) {
			return discovery.Result{}, false, nil
		},
		OpenTerminal: func(_ context.Context, _ *identity.Identity, _ *trust.Store, _ trust.Peer, dialer transport.Dialer, _ string) (coreapi.ConnectionHandle, error) {
			gotDialer = dialer
			return &testHandle{done: make(chan struct{})}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := backend.Open(context.Background(), peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Path != v1.ConnectionPathRelay {
		t.Fatalf("path = %q", opened.Path)
	}
	multi, ok := gotDialer.(transport.MultiDialer)
	if !ok {
		t.Fatalf("dialer type = %T", gotDialer)
	}
	if multi.WebRelay.ConnectionGrant != authorizer.grant || multi.WebRelay.TicketSource == nil {
		t.Fatal("web relay dialer did not receive authenticated grant/ticket source")
	}
}

func TestBackendLANIdentityMismatchFailsBeforeGrant(t *testing.T) {
	stateDir := t.TempDir()
	id := &identity.Identity{ID: "wd_aaaaaaaaaaaaaaaa"}
	peer := trust.Peer{ID: "wd_bbbbbbbbbbbbbbbb", Fingerprint: "trusted", Endpoint: "wsrelay://relay.example/wd_bbbbbbbbbbbbbbbb"}
	store := testBackendTrust(t, stateDir, peer)
	authorizer := &fakeAuthorizer{grant: "header.payload.signature"}
	backend, err := New(Config{
		StateDir:   stateDir,
		Identity:   id,
		Trust:      store,
		Authorizer: authorizer,
		FindTrusted: func(context.Context, string, string) (discovery.Result, bool, error) {
			return discovery.Result{}, false, discovery.ErrTrustedIdentityMismatch
		},
		OpenTerminal: func(context.Context, *identity.Identity, *trust.Store, trust.Peer, transport.Dialer, string) (coreapi.ConnectionHandle, error) {
			return nil, errors.New("must not open")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Open(context.Background(), peer.ID); !errors.Is(err, discovery.ErrTrustedIdentityMismatch) {
		t.Fatalf("Open error = %v", err)
	}
	if authorizer.grantCalls != 0 {
		t.Fatalf("grant calls = %d, want 0", authorizer.grantCalls)
	}
}

func TestBackendRoutedPathKeepsGrantAndRouteAuthorizationDistinct(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Date(2026, 9, 22, 18, 30, 0, 0, time.UTC)
	id := &identity.Identity{ID: "wd_aaaaaaaaaaaaaaaa"}
	destination := trust.Peer{ID: "wd_bbbbbbbbbbbbbbbb", Fingerprint: "unused-in-test"}
	routerID := "wd_cccccccccccccccc"
	store := testBackendTrust(t, stateDir, destination)
	routerTrust, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := routerTrust.Put(trust.Peer{ID: routerID, Fingerprint: "router-fingerprint", Endpoint: "tcp://127.0.0.1:7444"}); err != nil {
		t.Fatal(err)
	}

	route := mesh.Route{
		ID:          "route-test",
		Source:      mesh.DeviceID(id.ID),
		Destination: mesh.DeviceID(destination.ID),
		Hops: []mesh.RouteHop{
			{From: mesh.DeviceID(id.ID), To: mesh.DeviceID(routerID), Transport: mesh.TransportLAN, Cost: 10},
			{From: mesh.DeviceID(routerID), To: mesh.DeviceID(destination.ID), Transport: mesh.TransportInternet, Cost: 20},
		},
		ExpiresAt: now.Add(time.Minute),
	}
	authorizer := &fakeAuthorizer{
		grant: "header.payload.signature",
		route: route,
		authorization: mesh.RouteAuthorization{Claims: mesh.RouteAuthorizationClaims{
			Router:        mesh.DeviceID(routerID),
			Route:         route,
			ExpiresUnixMS: route.ExpiresAt.UnixMilli(),
		}},
	}
	request := account.RouteAuthorizationRequest{
		SourceDeviceID: id.ID, RouterDeviceID: routerID, DestinationDeviceID: destination.ID,
		FirstTransport: mesh.TransportLAN, SecondTransport: mesh.TransportInternet,
		FirstCost: 10, SecondCost: 20,
	}
	var gotDialer transport.Dialer
	backend, err := New(Config{
		StateDir:    stateDir,
		Identity:    id,
		Trust:       store,
		Authorizer:  authorizer,
		RouteSource: staticRouteSource{request: request, enabled: true},
		Now:         func() time.Time { return now },
		OpenTerminal: func(_ context.Context, _ *identity.Identity, _ *trust.Store, _ trust.Peer, dialer transport.Dialer, _ string) (coreapi.ConnectionHandle, error) {
			gotDialer = dialer
			return &testHandle{done: make(chan struct{})}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := backend.Open(context.Background(), destination.ID)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Path != v1.ConnectionPathRouted || opened.Route == nil || opened.Route.ID != route.ID {
		t.Fatalf("opened = %#v", opened)
	}
	if _, ok := gotDialer.(meshnet.RoutedDialer); !ok {
		t.Fatalf("dialer type = %T", gotDialer)
	}
	if len(authorizer.order) != 2 || authorizer.order[0] != "grant" || authorizer.order[1] != "route" {
		t.Fatalf("authorization order = %#v", authorizer.order)
	}
}

package main

import (
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/trust"
)

func TestBuildRoutedDialerUsesDedicatedRouterTrust(t *testing.T) {
	stateDir := t.TempDir()
	id, err := identity.Ensure(stateDir, "source")
	if err != nil {
		t.Fatal(err)
	}
	routerID := "wd_bbbbbbbbbbbbbbbb"
	destinationID := "wd_cccccccccccccccc"

	routeTrust, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := routeTrust.Put(trust.Peer{ID: routerID}); err != nil {
		t.Fatal(err)
	}

	route := mesh.Route{
		ID:          "00000000-0000-4000-8000-000000000001",
		Source:      mesh.DeviceID(id.ID),
		Destination: mesh.DeviceID(destinationID),
		Hops: []mesh.RouteHop{
			{From: mesh.DeviceID(id.ID), To: mesh.DeviceID(routerID), Transport: mesh.TransportLAN, Cost: 10},
			{From: mesh.DeviceID(routerID), To: mesh.DeviceID(destinationID), Transport: mesh.TransportLAN, Cost: 20},
		},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	auth := mesh.RouteAuthorization{
		Claims: mesh.RouteAuthorizationClaims{
			Router:        mesh.DeviceID(routerID),
			Route:         route,
			ExpiresUnixMS: route.ExpiresAt.UnixMilli(),
		},
	}

	dialer, err := buildRoutedDialer(stateDir, id, route, auth, 1500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if dialer.Identity != id || dialer.Route.ID != route.ID || dialer.Authorization.Claims.Router != mesh.DeviceID(routerID) {
		t.Fatalf("unexpected routed dialer: %+v", dialer)
	}
	resolver, ok := dialer.Resolver.(meshnet.TrustedPeerResolver)
	if !ok {
		t.Fatalf("resolver type = %T", dialer.Resolver)
	}
	if resolver.LANDiscoveryTimeout != 1500*time.Millisecond {
		t.Fatalf("LAN timeout = %s", resolver.LANDiscoveryTimeout)
	}
	if _, ok := resolver.Store.Get(routerID); !ok {
		t.Fatal("router missing from dedicated routing resolver trust")
	}
}

func TestBuildRoutedDialerRejectsRouterMismatch(t *testing.T) {
	stateDir := t.TempDir()
	id, err := identity.Ensure(stateDir, "source")
	if err != nil {
		t.Fatal(err)
	}
	route := mesh.Route{
		ID:          "00000000-0000-4000-8000-000000000001",
		Source:      mesh.DeviceID(id.ID),
		Destination: "wd_cccccccccccccccc",
		Hops: []mesh.RouteHop{
			{From: mesh.DeviceID(id.ID), To: "wd_bbbbbbbbbbbbbbbb", Transport: mesh.TransportLAN},
			{From: "wd_bbbbbbbbbbbbbbbb", To: "wd_cccccccccccccccc", Transport: mesh.TransportLAN},
		},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	auth := mesh.RouteAuthorization{Claims: mesh.RouteAuthorizationClaims{Router: "wd_dddddddddddddddd"}}

	if _, err := buildRoutedDialer(stateDir, id, route, auth, time.Second); err == nil {
		t.Fatal("mismatched route authorization router accepted")
	}
}

package main

import (
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/trust"
)

func TestBuildRoutedDialerRejectsMutatedAuthorizationRoute(t *testing.T) {
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

	expires := time.Now().Add(time.Minute)
	route := mesh.Route{
		ID:          "00000000-0000-4000-8000-000000000001",
		Source:      mesh.DeviceID(id.ID),
		Destination: mesh.DeviceID(destinationID),
		Hops: []mesh.RouteHop{
			{From: mesh.DeviceID(id.ID), To: mesh.DeviceID(routerID), Transport: mesh.TransportLAN, Cost: 10},
			{From: mesh.DeviceID(routerID), To: mesh.DeviceID(destinationID), Transport: mesh.TransportLAN, Cost: 20},
		},
		ExpiresAt: expires,
	}
	claimed := route
	claimed.Hops = append([]mesh.RouteHop(nil), route.Hops...)
	claimed.Hops[1].Cost++

	auth := mesh.RouteAuthorization{Claims: mesh.RouteAuthorizationClaims{
		Router:        mesh.DeviceID(routerID),
		Route:         claimed,
		ExpiresUnixMS: expires.UnixMilli(),
	}}

	if _, err := buildRoutedDialer(stateDir, id, route, auth, time.Second); err == nil {
		t.Fatal("mutated signed route accepted")
	}
}

func TestBuildRoutedDialerRejectsStaleAuthorizationBeforeTrust(t *testing.T) {
	stateDir := t.TempDir()
	id, err := identity.Ensure(stateDir, "source")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	route := mesh.Route{
		ID:          "00000000-0000-4000-8000-000000000001",
		Source:      mesh.DeviceID(id.ID),
		Destination: "wd_cccccccccccccccc",
		Hops: []mesh.RouteHop{
			{From: mesh.DeviceID(id.ID), To: "wd_bbbbbbbbbbbbbbbb", Transport: mesh.TransportLAN},
			{From: "wd_bbbbbbbbbbbbbbbb", To: "wd_cccccccccccccccc", Transport: mesh.TransportLAN},
		},
		ExpiresAt: now.Add(time.Minute),
	}
	auth := mesh.RouteAuthorization{Claims: mesh.RouteAuthorizationClaims{
		Router:        "wd_bbbbbbbbbbbbbbbb",
		Route:         route,
		ExpiresUnixMS: now.Add(-time.Second).UnixMilli(),
	}}

	_, err = buildRoutedDialer(stateDir, id, route, auth, time.Second)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildRoutedDialerRejectsMalformedRouteBeforeTrust(t *testing.T) {
	stateDir := t.TempDir()
	id, err := identity.Ensure(stateDir, "source")
	if err != nil {
		t.Fatal(err)
	}

	expires := time.Now().Add(time.Minute)
	route := mesh.Route{
		ID:          "00000000-0000-4000-8000-000000000001",
		Source:      mesh.DeviceID(id.ID),
		Destination: "wd_cccccccccccccccc",
		Hops: []mesh.RouteHop{
			{From: mesh.DeviceID(id.ID), To: "wd_bbbbbbbbbbbbbbbb", Transport: mesh.TransportLAN},
			{From: mesh.DeviceID(id.ID), To: "wd_cccccccccccccccc", Transport: mesh.TransportLAN},
		},
		ExpiresAt: expires,
	}
	auth := mesh.RouteAuthorization{Claims: mesh.RouteAuthorizationClaims{
		Router:        "wd_bbbbbbbbbbbbbbbb",
		Route:         route,
		ExpiresUnixMS: expires.UnixMilli(),
	}}

	_, err = buildRoutedDialer(stateDir, id, route, auth, time.Second)
	if err == nil || !strings.Contains(err.Error(), "discontinuous") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "not trusted for routing") {
		t.Fatalf("malformed route reached routing trust lookup: %v", err)
	}
}

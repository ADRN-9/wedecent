package coreapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/mesh"
)

func TestNetworkReadServiceTransportStatusIsDeterministicAndCopied(t *testing.T) {
	service, err := NewNetworkReadService("wd_source00000000", []v1.TransportStatus{
		{Name: v1.TransportBluetooth, Available: false, Detail: "not implemented"},
		{Name: v1.TransportInternet, Available: true},
		{Name: v1.TransportLAN, Available: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := service.GetTransportStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []v1.TransportName{v1.TransportLAN, v1.TransportInternet, v1.TransportBluetooth}
	if len(got) != len(wantNames) {
		t.Fatalf("transport count = %d, want %d", len(got), len(wantNames))
	}
	for i, want := range wantNames {
		if got[i].Name != want {
			t.Fatalf("transport[%d] = %q, want %q", i, got[i].Name, want)
		}
	}

	got[0].Available = false
	again, err := service.GetTransportStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !again[0].Available {
		t.Fatal("caller mutation changed stored transport status")
	}
}

func TestNetworkReadServiceRejectsDuplicateAndUnsafeTransportStatus(t *testing.T) {
	for name, statuses := range map[string][]v1.TransportStatus{
		"duplicate": {
			{Name: v1.TransportLAN, Available: true},
			{Name: v1.TransportLAN, Available: false},
		},
		"unknown": {{Name: "usb", Available: true}},
		"control detail": {{Name: v1.TransportLAN, Detail: "line\nbreak"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewNetworkReadService("wd_source00000000", statuses); err == nil {
				t.Fatal("NewNetworkReadService succeeded")
			}
		})
	}
}

func TestNetworkReadServiceRoutedStatusUsesValidatedMeshRoute(t *testing.T) {
	now := time.Date(2026, 9, 22, 17, 0, 0, 0, time.UTC)
	service, err := NewNetworkReadService("wd_source00000000", DefaultTransportStatuses())
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	route := mesh.Route{
		ID:          "route-1",
		Source:      "wd_source00000000",
		Destination: "wd_dest0000000000",
		Hops: []mesh.RouteHop{
			{From: "wd_source00000000", To: "wd_router00000000", Transport: mesh.TransportLAN, Cost: 10},
			{From: "wd_router00000000", To: "wd_dest0000000000", Transport: mesh.TransportInternet, Cost: 20},
		},
		ExpiresAt: now.Add(time.Minute),
	}
	if err := service.SetConnectionPath(ConnectionPathSnapshot{
		ConnectionID:  "connection-1",
		DestinationID: "wd_dest0000000000",
		Path:          v1.ConnectionPathRouted,
		Route:         &route,
	}); err != nil {
		t.Fatal(err)
	}

	// Mutating the caller's route after recording must not mutate UI-visible state.
	route.Hops[0].Cost = 999

	got, err := service.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: "connection-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ConnectionID != "connection-1" || got.DestinationID != "wd_dest0000000000" || got.Path != v1.ConnectionPathRouted {
		t.Fatalf("status = %#v", got)
	}
	if got.RouterID != "wd_router00000000" {
		t.Fatalf("router ID = %q", got.RouterID)
	}
	wantHops := []v1.RouteHop{
		{From: "wd_source00000000", To: "wd_router00000000", Transport: v1.TransportLAN, Cost: 10},
		{From: "wd_router00000000", To: "wd_dest0000000000", Transport: v1.TransportInternet, Cost: 20},
	}
	if !reflect.DeepEqual(got.Hops, wantHops) {
		t.Fatalf("hops = %#v, want %#v", got.Hops, wantHops)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("expires = %v", got.ExpiresAt)
	}

	got.Hops[0].Cost = 555
	again, err := service.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: "connection-1"})
	if err != nil {
		t.Fatal(err)
	}
	if again.Hops[0].Cost != 10 {
		t.Fatalf("caller mutation changed stored route: %#v", again.Hops)
	}
}

func TestNetworkReadServiceExpiredRouteDisappearsFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 22, 17, 0, 0, 0, time.UTC)
	service, err := NewNetworkReadService("wd_source00000000", DefaultTransportStatuses())
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	route := mesh.Route{
		ID:          "route-1",
		Source:      "wd_source00000000",
		Destination: "wd_dest0000000000",
		Hops: []mesh.RouteHop{
			{From: "wd_source00000000", To: "wd_router00000000", Transport: mesh.TransportLAN},
			{From: "wd_router00000000", To: "wd_dest0000000000", Transport: mesh.TransportInternet},
		},
		ExpiresAt: now.Add(time.Second),
	}
	if err := service.SetConnectionPath(ConnectionPathSnapshot{
		ConnectionID:  "connection-1",
		DestinationID: "wd_dest0000000000",
		Path:          v1.ConnectionPathRouted,
		Route:         &route,
	}); err != nil {
		t.Fatal(err)
	}

	now = now.Add(time.Second)
	_, err = service.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: "connection-1"})
	if !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("expired route error = %v, want ErrRouteNotFound", err)
	}
	_, err = service.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: "connection-1"})
	if !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("removed route error = %v, want ErrRouteNotFound", err)
	}
}

func TestNetworkReadServiceNonRoutedStatusContainsNoRouteMaterial(t *testing.T) {
	service, err := NewNetworkReadService("wd_source00000000", DefaultTransportStatuses())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetConnectionPath(ConnectionPathSnapshot{
		ConnectionID:  "connection-2",
		DestinationID: "wd_dest0000000000",
		Path:          v1.ConnectionPathRelay,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := service.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: "connection-2"})
	if err != nil {
		t.Fatal(err)
	}
	if got.RouterID != "" || len(got.Hops) != 0 || got.ExpiresAt != nil {
		t.Fatalf("non-routed status contains route material: %#v", got)
	}

	service.RemoveConnectionPath("connection-2")
	_, err = service.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: "connection-2"})
	if !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("removed status error = %v, want ErrRouteNotFound", err)
	}
}

func TestNetworkReadServiceRejectsMismatchedOrMalformedSnapshots(t *testing.T) {
	now := time.Date(2026, 9, 22, 17, 0, 0, 0, time.UTC)
	service, err := NewNetworkReadService("wd_source00000000", DefaultTransportStatuses())
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	validRoute := mesh.Route{
		ID:          "route-1",
		Source:      "wd_source00000000",
		Destination: "wd_dest0000000000",
		Hops: []mesh.RouteHop{
			{From: "wd_source00000000", To: "wd_router00000000", Transport: mesh.TransportLAN},
			{From: "wd_router00000000", To: "wd_dest0000000000", Transport: mesh.TransportInternet},
		},
		ExpiresAt: now.Add(time.Minute),
	}

	cases := []ConnectionPathSnapshot{
		{ConnectionID: " bad", DestinationID: "wd_dest0000000000", Path: v1.ConnectionPathRelay},
		{ConnectionID: "connection", DestinationID: "", Path: v1.ConnectionPathRelay},
		{ConnectionID: "connection", DestinationID: "wd_dest0000000000", Path: "unknown"},
		{ConnectionID: "connection", DestinationID: "wd_dest0000000000", Path: v1.ConnectionPathRouted},
		{ConnectionID: "connection", DestinationID: "wd_dest0000000000", Path: v1.ConnectionPathRelay, Route: &validRoute},
	}
	wrongSource := validRoute
	wrongSource.Source = "wd_other000000000"
	wrongSource.Hops[0].From = wrongSource.Source
	cases = append(cases, ConnectionPathSnapshot{
		ConnectionID: "connection", DestinationID: "wd_dest0000000000", Path: v1.ConnectionPathRouted, Route: &wrongSource,
	})

	for i, snapshot := range cases {
		if err := service.SetConnectionPath(snapshot); err == nil {
			t.Fatalf("case %d succeeded: %#v", i, snapshot)
		}
	}
}

func TestNetworkReadServiceHonorsCancellationAndValidatesQueries(t *testing.T) {
	service, err := NewNetworkReadService("wd_source00000000", DefaultTransportStatuses())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.GetTransportStatus(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("transport status error = %v", err)
	}
	if _, err := service.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{}); !errors.Is(err, ErrInvalidRouteRequest) {
		t.Fatalf("empty route request error = %v", err)
	}
}

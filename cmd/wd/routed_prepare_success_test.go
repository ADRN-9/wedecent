package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/trust"
)

func TestPrepareRoutedDialerIssuesExactAuthorization(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "client")
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

	now := time.UnixMilli(1800000001000).UTC()
	expires := now.Add(60 * time.Second)
	var calls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/functions/v1/route-authorization" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer access" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}

		var body struct {
			Source          string `json:"source_device_id"`
			Router          string `json:"router_device_id"`
			Destination     string `json:"destination_device_id"`
			FirstTransport  string `json:"first_transport"`
			SecondTransport string `json:"second_transport"`
			FirstCost       uint64 `json:"first_cost"`
			SecondCost      uint64 `json:"second_cost"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Source != id.ID || body.Router != routerID || body.Destination != destinationID ||
			body.FirstTransport != "lan" || body.SecondTransport != "internet" ||
			body.FirstCost != 10 || body.SecondCost != 20 {
			t.Fatalf("unexpected route authorization request: %+v", body)
		}

		route := mesh.Route{
			ID:          "00000000-0000-4000-8000-000000000001",
			Source:      mesh.DeviceID(id.ID),
			Destination: mesh.DeviceID(destinationID),
			Hops: []mesh.RouteHop{
				{From: mesh.DeviceID(id.ID), To: mesh.DeviceID(routerID), Transport: mesh.TransportLAN, Cost: 10},
				{From: mesh.DeviceID(routerID), To: mesh.DeviceID(destinationID), Transport: mesh.TransportInternet, Cost: 20},
			},
			ExpiresAt: expires,
		}
		auth := mesh.RouteAuthorization{
			KeyID: "route-key-1",
			Claims: mesh.RouteAuthorizationClaims{
				Version:        mesh.RouteAuthorizationVersion,
				Issuer:         mesh.RouteAuthorizationIssuer,
				Audience:       mesh.RouteAuthorizationAudience,
				Permission:     mesh.RouteAuthorizationPermission,
				JTI:            base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
				Router:         mesh.DeviceID(routerID),
				Route:          route,
				IssuedAtUnixMS: now.Add(-time.Second).UnixMilli(),
				ExpiresUnixMS:  expires.UnixMilli(),
			},
			Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"route": route, "authorization": auth})
	}))
	defer server.Close()

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

	dialer, enabled, err := prepareRoutedDialer(
		context.Background(),
		stateDir,
		id,
		destinationID,
		routedConnectConfig{
			RouterDeviceID:  routerID,
			FirstTransport:  "lan",
			SecondTransport: "internet",
			FirstCost:       10,
			SecondCost:      20,
		},
		1500*time.Millisecond,
		account.Client{HTTP: server.Client(), Now: func() time.Time { return now }},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatal("routed dialer was not enabled")
	}
	if calls.Load() != 1 {
		t.Fatalf("authorization HTTP calls = %d, want 1", calls.Load())
	}
	if dialer.Route.Source != mesh.DeviceID(id.ID) ||
		dialer.Route.Destination != mesh.DeviceID(destinationID) ||
		dialer.Authorization.Claims.Router != mesh.DeviceID(routerID) {
		t.Fatalf("unexpected routed dialer")
	}
}

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/mesh"
)

func TestAutomaticRouteAuthorization(t *testing.T) {
	now := time.UnixMilli(1800000001000).UTC()
	expires := now.Add(60 * time.Second)
	request := account.RouteAuthorizationRequest{
		SourceDeviceID:      "wd_aaaaaaaaaaaaaaaa",
		RouterDeviceID:      "wd_bbbbbbbbbbbbbbbb",
		DestinationDeviceID: "wd_cccccccccccccccc",
		FirstTransport:      mesh.TransportLAN,
		SecondTransport:     mesh.TransportInternet,
		FirstCost:           10,
		SecondCost:          20,
	}
	route := mesh.Route{
		ID:          "00000000-0000-4000-8000-000000000001",
		Source:      "wd_aaaaaaaaaaaaaaaa",
		Destination: "wd_cccccccccccccccc",
		Hops: []mesh.RouteHop{
			{From: "wd_aaaaaaaaaaaaaaaa", To: "wd_bbbbbbbbbbbbbbbb", Transport: mesh.TransportLAN, Cost: 10},
			{From: "wd_bbbbbbbbbbbbbbbb", To: "wd_cccccccccccccccc", Transport: mesh.TransportInternet, Cost: 20},
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
			Router:         "wd_bbbbbbbbbbbbbbbb",
			Route:          route,
			IssuedAtUnixMS: now.Add(-time.Second).UnixMilli(),
			ExpiresUnixMS:  expires.UnixMilli(),
		},
		Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		if body.Source != request.SourceDeviceID || body.Router != request.RouterDeviceID || body.Destination != request.DestinationDeviceID || body.FirstTransport != string(request.FirstTransport) || body.SecondTransport != string(request.SecondTransport) || body.FirstCost != request.FirstCost || body.SecondCost != request.SecondCost {
			t.Fatalf("unexpected request: %+v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"route": route, "authorization": auth})
	}))
	defer server.Close()

	stateDir := filepath.Join(t.TempDir(), "client")
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

	gotRoute, gotAuth, err := automaticRouteAuthorization(context.Background(), stateDir, request, account.Client{HTTP: server.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if gotRoute.ID != route.ID || gotAuth.Claims.Router != "wd_bbbbbbbbbbbbbbbb" {
		t.Fatalf("route/auth mismatch: route=%q router=%q", gotRoute.ID, gotAuth.Claims.Router)
	}
}

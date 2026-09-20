package account

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

func TestIssueRouteAuthorization(t *testing.T) {
	t.Parallel()

	now := time.UnixMilli(
		1_800_000_001_000,
	).UTC()

	request := RouteAuthorizationRequest{
		SourceDeviceID:      "wd_aaaaaaaaaaaaaaaa",
		RouterDeviceID:      "wd_bbbbbbbbbbbbbbbb",
		DestinationDeviceID: "wd_cccccccccccccccc",
		FirstTransport:      mesh.TransportInternet,
		SecondTransport:     mesh.TransportLAN,
		FirstCost:           10,
		SecondCost:          20,
	}

	response := routeAuthorizationTestResponse(
		now,
		request,
	)

	var calls atomic.Int32

	server := httptest.NewServer(
		http.HandlerFunc(func(
			w http.ResponseWriter,
			r *http.Request,
		) {
			calls.Add(1)

			if r.URL.Path !=
				"/functions/v1/route-authorization" {
				t.Errorf(
					"path = %q",
					r.URL.Path,
				)
			}

			if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
				t.Errorf(
					"Authorization = %q",
					got,
				)
			}

			if got := r.Header.Get("apikey"); got != "publishable-key" {
				t.Errorf(
					"apikey = %q",
					got,
				)
			}

			var body struct {
				SourceDeviceID      string `json:"source_device_id"`
				RouterDeviceID      string `json:"router_device_id"`
				DestinationDeviceID string `json:"destination_device_id"`
				FirstTransport      string `json:"first_transport"`
				SecondTransport     string `json:"second_transport"`
				FirstCost           uint64 `json:"first_cost"`
				SecondCost          uint64 `json:"second_cost"`
			}

			if err := json.NewDecoder(r.Body).
				Decode(&body); err != nil {
				t.Error(err)
				return
			}

			if body.SourceDeviceID !=
				request.SourceDeviceID ||
				body.RouterDeviceID !=
					request.RouterDeviceID ||
				body.DestinationDeviceID !=
					request.DestinationDeviceID ||
				body.FirstTransport !=
					string(request.FirstTransport) ||
				body.SecondTransport !=
					string(request.SecondTransport) ||
				body.FirstCost !=
					request.FirstCost ||
				body.SecondCost !=
					request.SecondCost {
				t.Errorf(
					"unexpected request body: %+v",
					body,
				)
			}

			w.Header().Set(
				"Content-Type",
				"application/json",
			)

			if err := json.NewEncoder(w).
				Encode(response); err != nil {
				t.Error(err)
			}
		}),
	)
	defer server.Close()

	session := &Session{
		Version:        SessionVersion,
		SupabaseURL:    server.URL,
		PublishableKey: "publishable-key",
		UserID:         "user-id",
		Email:          "user@example.com",
		AccessToken:    "access-token",
		RefreshToken:   "refresh-token",
		ExpiresAt:      now.Add(time.Hour).Unix(),
	}

	client := Client{
		HTTP: server.Client(),
		Now:  func() time.Time { return now },
	}

	route, authorization, err :=
		client.IssueRouteAuthorization(
			context.Background(),
			session,
			request,
		)

	if err != nil {
		t.Fatal(err)
	}

	if route.ID != response.Route.ID {
		t.Fatalf(
			"route ID = %q, want %q",
			route.ID,
			response.Route.ID,
		)
	}

	if authorization.Claims.Router !=
		mesh.DeviceID(request.RouterDeviceID) {
		t.Fatalf(
			"router = %q",
			authorization.Claims.Router,
		)
	}

	if calls.Load() != 1 {
		t.Fatalf(
			"HTTP calls = %d, want 1",
			calls.Load(),
		)
	}
}

func TestIssueRouteAuthorizationRejectsMismatchedClaims(
	t *testing.T,
) {
	t.Parallel()

	now := time.UnixMilli(
		1_800_000_100_000,
	).UTC()

	request := RouteAuthorizationRequest{
		SourceDeviceID:      "wd_aaaaaaaaaaaaaaaa",
		RouterDeviceID:      "wd_bbbbbbbbbbbbbbbb",
		DestinationDeviceID: "wd_cccccccccccccccc",
		FirstTransport:      mesh.TransportInternet,
		SecondTransport:     mesh.TransportInternet,
		FirstCost:           1,
		SecondCost:          2,
	}

	response := routeAuthorizationTestResponse(
		now,
		request,
	)

	response.Authorization.Claims.Router =
		"wd_dddddddddddddddd"

	server := httptest.NewServer(
		http.HandlerFunc(func(
			w http.ResponseWriter,
			_ *http.Request,
		) {
			w.Header().Set(
				"Content-Type",
				"application/json",
			)
			_ = json.NewEncoder(w).
				Encode(response)
		}),
	)
	defer server.Close()

	session := &Session{
		Version:        SessionVersion,
		SupabaseURL:    server.URL,
		PublishableKey: "publishable-key",
		AccessToken:    "access-token",
		RefreshToken:   "refresh-token",
		ExpiresAt:      now.Add(time.Hour).Unix(),
	}

	client := Client{
		HTTP: server.Client(),
		Now:  func() time.Time { return now },
	}

	_, _, err := client.IssueRouteAuthorization(
		context.Background(),
		session,
		request,
	)

	if err == nil {
		t.Fatal(
			"mismatched authorization claims accepted",
		)
	}
}

func TestIssueRouteAuthorizationRejectsInvalidRequestBeforeNetwork(
	t *testing.T,
) {
	t.Parallel()

	var calls atomic.Int32

	server := httptest.NewServer(
		http.HandlerFunc(func(
			http.ResponseWriter,
			*http.Request,
		) {
			calls.Add(1)
		}),
	)
	defer server.Close()

	now := time.Now().UTC()

	session := &Session{
		Version:        SessionVersion,
		SupabaseURL:    server.URL,
		PublishableKey: "publishable-key",
		AccessToken:    "access-token",
		RefreshToken:   "refresh-token",
		ExpiresAt:      now.Add(time.Hour).Unix(),
	}

	client := Client{
		HTTP: server.Client(),
		Now:  func() time.Time { return now },
	}

	_, _, err := client.IssueRouteAuthorization(
		context.Background(),
		session,
		RouteAuthorizationRequest{
			SourceDeviceID:      "wd_aaaaaaaaaaaaaaaa",
			RouterDeviceID:      "wd_aaaaaaaaaaaaaaaa",
			DestinationDeviceID: "wd_cccccccccccccccc",
			FirstTransport:      mesh.TransportInternet,
			SecondTransport:     mesh.TransportInternet,
		},
	)

	if err == nil {
		t.Fatal("invalid request accepted")
	}

	if calls.Load() != 0 {
		t.Fatalf(
			"HTTP calls = %d, want 0",
			calls.Load(),
		)
	}
}

func routeAuthorizationTestResponse(
	now time.Time,
	request RouteAuthorizationRequest,
) routeAuthorizationResponse {
	expiresAt := time.UnixMilli(
		now.Add(60 * time.Second).
			UnixMilli(),
	).UTC()

	route := mesh.Route{
		ID: "00000000-0000-4000-8000-000000000001",
		Source: mesh.DeviceID(
			request.SourceDeviceID,
		),
		Destination: mesh.DeviceID(
			request.DestinationDeviceID,
		),
		Hops: []mesh.RouteHop{
			{
				From: mesh.DeviceID(
					request.SourceDeviceID,
				),
				To: mesh.DeviceID(
					request.RouterDeviceID,
				),
				Transport: request.FirstTransport,
				Cost:      request.FirstCost,
			},
			{
				From: mesh.DeviceID(
					request.RouterDeviceID,
				),
				To: mesh.DeviceID(
					request.DestinationDeviceID,
				),
				Transport: request.SecondTransport,
				Cost:      request.SecondCost,
			},
		},
		ExpiresAt: expiresAt,
	}

	rawJTI := make([]byte, 16)
	for index := range rawJTI {
		rawJTI[index] = byte(index)
	}

	signature := make(
		[]byte,
		ed25519.SignatureSize,
	)

	return routeAuthorizationResponse{
		Route: route,
		Authorization: mesh.RouteAuthorization{
			KeyID: "route-key-1",
			Claims: mesh.RouteAuthorizationClaims{
				Version:    mesh.RouteAuthorizationVersion,
				Issuer:     mesh.RouteAuthorizationIssuer,
				Audience:   mesh.RouteAuthorizationAudience,
				Permission: mesh.RouteAuthorizationPermission,
				JTI: base64.RawURLEncoding.
					EncodeToString(rawJTI),
				Router: mesh.DeviceID(
					request.RouterDeviceID,
				),
				Route: route,
				IssuedAtUnixMS: now.Add(-time.Second).
					UnixMilli(),
				ExpiresUnixMS: expiresAt.UnixMilli(),
			},
			Signature: base64.RawURLEncoding.
				EncodeToString(signature),
		},
	}
}

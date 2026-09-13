package mesh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type routeAuthorizationLocalAuthorizerFunc func(
	context.Context,
	ForwardRequest,
) error

func (f routeAuthorizationLocalAuthorizerFunc) AuthorizeForward(
	ctx context.Context,
	request ForwardRequest,
) error {
	return f(ctx, request)
}

type routeAuthorizationReplayProbe struct {
	consumed atomic.Bool
}

func (r *routeAuthorizationReplayProbe) ConsumeRouteAuthorization(
	ctx context.Context,
	_ string,
	_ time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.consumed.Store(true)
	return nil
}

type routeAuthorizationIntegrationLink struct {
	net.Conn
	local     DeviceID
	remote    DeviceID
	transport TransportName
}

func (l *routeAuthorizationIntegrationLink) Local() DeviceID {
	return l.local
}

func (l *routeAuthorizationIntegrationLink) Remote() DeviceID {
	return l.remote
}

func (l *routeAuthorizationIntegrationLink) Transport() TransportName {
	return l.transport
}

func routeAuthorizationIntegrationRoute(now time.Time) Route {
	return Route{
		ID:          "route-signed-a-b-c",
		Source:      "wd_a",
		Destination: "wd_c",
		ExpiresAt:   now.Add(90 * time.Second),
		Hops: []RouteHop{
			{
				From:      "wd_a",
				To:        "wd_b",
				Transport: TransportLAN,
				Cost:      10,
			},
			{
				From:      "wd_b",
				To:        "wd_c",
				Transport: TransportInternet,
				Cost:      20,
			},
		},
	}
}

func routeAuthorizationIntegrationAuth(
	t *testing.T,
	now time.Time,
	route Route,
) (
	RouteAuthorization,
	ed25519.PublicKey,
) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jti, err := NewRouteAuthorizationJTI()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-integration",
		NewRouteAuthorizationClaims(
			route,
			"wd_b",
			jti,
			now,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	return auth, publicKey
}

func TestRouteAuthorizationLocalDenialDoesNotConsumeJTI(
	t *testing.T,
) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Millisecond)
	route := routeAuthorizationIntegrationRoute(now)

	auth, publicKey := routeAuthorizationIntegrationAuth(
		t,
		now,
		route,
	)

	replay := &routeAuthorizationReplayProbe{}
	localDenied := errors.New("test: local policy denied")

	authorizer := RouteAuthorizationForwardAuthorizer{
		LocalAuthorizer: routeAuthorizationLocalAuthorizerFunc(
			func(
				context.Context,
				ForwardRequest,
			) error {
				return localDenied
			},
		),
		Verifier: RouteAuthorizationVerifier{
			KeyID:     "control-key-integration",
			PublicKey: publicKey,
			Replay:    replay,
			Now:       func() time.Time { return now },
		},
	}

	err := authorizer.AuthorizeForward(
		context.Background(),
		ForwardRequest{
			Router:        "wd_b",
			Route:         route,
			Authorization: auth,
			Policy: RouterPolicy{
				Enabled:            true,
				TrustedDevicesOnly: true,
			},
		},
	)

	if !errors.Is(err, localDenied) {
		t.Fatalf(
			"AuthorizeForward() error = %v, want local denial",
			err,
		)
	}

	if replay.consumed.Load() {
		t.Fatal("local policy denial consumed authorization JTI")
	}
}

func TestRouteAuthorizationLocalMutationCannotAlterVerification(
	t *testing.T,
) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Millisecond)
	route := routeAuthorizationIntegrationRoute(now)

	auth, publicKey := routeAuthorizationIntegrationAuth(
		t,
		now,
		route,
	)

	replay := &routeAuthorizationReplayProbe{}

	authorizer := RouteAuthorizationForwardAuthorizer{
		LocalAuthorizer: routeAuthorizationLocalAuthorizerFunc(
			func(
				_ context.Context,
				request ForwardRequest,
			) error {
				request.Route.Hops[0].To = "wd_mutated"
				request.Authorization.Claims.Route.Hops[0].To =
					"wd_mutated"
				request.Authorization.Signature =
					"mutated-signature"
				return nil
			},
		),
		Verifier: RouteAuthorizationVerifier{
			KeyID:     "control-key-integration",
			PublicKey: publicKey,
			Replay:    replay,
			Now:       func() time.Time { return now },
		},
	}

	if err := authorizer.AuthorizeForward(
		context.Background(),
		ForwardRequest{
			Router:        "wd_b",
			Route:         route,
			Authorization: auth,
			Policy: RouterPolicy{
				Enabled:            true,
				TrustedDevicesOnly: true,
			},
		},
	); err != nil {
		t.Fatalf(
			"AuthorizeForward() after mutation attempt: %v",
			err,
		)
	}

	if !replay.consumed.Load() {
		t.Fatal("valid authorization was not consumed")
	}

	if route.Hops[0].To != "wd_b" {
		t.Fatalf("caller route mutated: %+v", route)
	}

	if auth.Claims.Route.Hops[0].To != "wd_b" {
		t.Fatalf(
			"caller authorization mutated: %+v",
			auth.Claims.Route,
		)
	}
}

func TestServeRouteOpenSignedAuthorizationConsumedBeforeDial(
	t *testing.T,
) {
	t.Parallel()

	clientSide, routerSide := net.Pipe()
	defer clientSide.Close()

	if err := clientSide.SetDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	route := routeAuthorizationIntegrationRoute(now)

	auth, publicKey := routeAuthorizationIntegrationAuth(
		t,
		now,
		route,
	)

	replay := &routeAuthorizationReplayProbe{}
	var dialed atomic.Bool
	var orderViolation atomic.Bool

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
			MaxSessions:        1,
		},
		Authorizer: RouteAuthorizationForwardAuthorizer{
			LocalAuthorizer: routeAuthorizationLocalAuthorizerFunc(
				func(
					context.Context,
					ForwardRequest,
				) error {
					return nil
				},
			),
			Verifier: RouteAuthorizationVerifier{
				KeyID:     "control-key-integration",
				PublicKey: publicKey,
				Replay:    replay,
				Now:       func() time.Time { return now },
			},
		},
		DialNext: func(
			context.Context,
			RouteHop,
		) (Link, error) {
			if !replay.consumed.Load() {
				orderViolation.Store(true)
			}
			dialed.Store(true)

			// Stop after proving ordering; no tunnel copy is needed here.
			return nil, errors.New(
				"test: intentional destination dial failure",
			)
		},
		Now: func() time.Time { return now },
	}

	serverDone := make(chan error, 1)

	go func() {
		_, err := forwarder.ServeRouteOpen(
			context.Background(),
			&routeAuthorizationIntegrationLink{
				Conn:      routerSide,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		serverDone <- err
	}()

	if err := WriteRouteOpenRequest(
		clientSide,
		RouteOpenRequest{
			Route:         route,
			Authorization: auth,
		},
	); err != nil {
		t.Fatalf("WriteRouteOpenRequest() error: %v", err)
	}

	resp, err := ReadRouteOpenResponse(clientSide)
	if err != nil {
		t.Fatalf("ReadRouteOpenResponse() error: %v", err)
	}

	if resp.Accepted ||
		resp.Code != RouteOpenCodeUnavailable {
		t.Fatalf(
			"route-open response = %+v, want unavailable after test dial failure",
			resp,
		)
	}

	if !replay.consumed.Load() {
		t.Fatal("signed route authorization was not consumed")
	}
	if !dialed.Load() {
		t.Fatal("destination dial was not attempted")
	}
	if orderViolation.Load() {
		t.Fatal(
			"DialNext ran before signed authorization replay consumption",
		)
	}

	if err := <-serverDone; err == nil {
		t.Fatal("ServeRouteOpen() unexpectedly succeeded")
	}
}

func TestServeRouteOpenRejectsMissingSignedAuthorizationBeforeDial(
	t *testing.T,
) {
	t.Parallel()

	clientSide, routerSide := net.Pipe()
	defer clientSide.Close()

	if err := clientSide.SetDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	route := routeAuthorizationIntegrationRoute(now)

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	replay := &routeAuthorizationReplayProbe{}
	var dialed atomic.Bool

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
			MaxSessions:        1,
		},
		Authorizer: RouteAuthorizationForwardAuthorizer{
			LocalAuthorizer: routeAuthorizationLocalAuthorizerFunc(
				func(
					context.Context,
					ForwardRequest,
				) error {
					return nil
				},
			),
			Verifier: RouteAuthorizationVerifier{
				KeyID:     "control-key-integration",
				PublicKey: publicKey,
				Replay:    replay,
				Now:       func() time.Time { return now },
			},
		},
		DialNext: func(
			context.Context,
			RouteHop,
		) (Link, error) {
			dialed.Store(true)
			return nil, nil
		},
		Now: func() time.Time { return now },
	}

	serverDone := make(chan error, 1)

	go func() {
		_, err := forwarder.ServeRouteOpen(
			context.Background(),
			&routeAuthorizationIntegrationLink{
				Conn:      routerSide,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		serverDone <- err
	}()

	// Deliberately omit a usable signed capability.
	if err := WriteRouteOpenRequest(
		clientSide,
		RouteOpenRequest{
			Route: route,
		},
	); err != nil {
		t.Fatalf("WriteRouteOpenRequest() error: %v", err)
	}

	resp, err := ReadRouteOpenResponse(clientSide)
	if err != nil {
		t.Fatalf("ReadRouteOpenResponse() error: %v", err)
	}

	if resp.Accepted ||
		resp.Code != RouteOpenCodeDenied {
		t.Fatalf(
			"route-open response = %+v, want generic denial",
			resp,
		)
	}

	if replay.consumed.Load() {
		t.Fatal(
			"invalid/missing authorization consumed replay state",
		)
	}
	if dialed.Load() {
		t.Fatal(
			"missing signed authorization reached DialNext",
		)
	}

	if err := <-serverDone; !errors.Is(
		err,
		ErrForwardDenied,
	) {
		t.Fatalf(
			"ServeRouteOpen() error = %v, want ErrForwardDenied",
			err,
		)
	}
}

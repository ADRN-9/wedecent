package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRouteAuthorizationCanonicalStringFramingIsUnambiguous(
	t *testing.T,
) {
	t.Parallel()

	// These two logical sequences collapse under a naive newline-delimited
	// representation:
	//
	//	["alpha\nsource=beta", "gamma"]
	//	["alpha", "source=beta\ngamma"]
	//
	// Explicit length framing must keep them distinct.
	var left bytes.Buffer
	if err := writeRouteAuthorizationString(
		&left,
		"alpha\nsource=beta",
	); err != nil {
		t.Fatal(err)
	}
	if err := writeRouteAuthorizationString(
		&left,
		"gamma",
	); err != nil {
		t.Fatal(err)
	}

	var right bytes.Buffer
	if err := writeRouteAuthorizationString(
		&right,
		"alpha",
	); err != nil {
		t.Fatal(err)
	}
	if err := writeRouteAuthorizationString(
		&right,
		"source=beta\ngamma",
	); err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(left.Bytes(), right.Bytes()) {
		t.Fatal(
			"distinct authorization fields produced identical canonical bytes",
		)
	}
}

func TestRouteAuthorizationCanonicalizesEmbeddedRouteExpiry(
	t *testing.T,
) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_001_000_000).UTC()

	// Deliberately give the runtime route sub-millisecond precision.
	route := routeAuthorizationTestRoute(
		now.Add(
			90*time.Second +
				987*time.Microsecond +
				654*time.Nanosecond,
		),
	)

	claims := NewRouteAuthorizationClaims(
		route,
		"wd_b",
		routeAuthorizationTestJTI(12),
		now,
	)

	wantExpiry := time.UnixMilli(
		route.ExpiresAt.UTC().UnixMilli(),
	).UTC()

	if claims.Route.ExpiresAt != wantExpiry {
		t.Fatalf(
			"embedded route expiry = %v, want canonical %v",
			claims.Route.ExpiresAt,
			wantExpiry,
		)
	}

	if claims.ExpiresUnixMS != wantExpiry.UnixMilli() {
		t.Fatalf(
			"ExpiresUnixMS = %d, want %d",
			claims.ExpiresUnixMS,
			wantExpiry.UnixMilli(),
		)
	}

	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-1",
		claims,
	)
	if err != nil {
		t.Fatal(err)
	}

	replay := NewMemoryRouteAuthorizationReplay()
	replay.now = func() time.Time { return now }

	verifier := RouteAuthorizationVerifier{
		KeyID:     "control-key-1",
		PublicKey: publicKey,
		Replay:    replay,
		Now:       func() time.Time { return now },
	}

	mutations := []struct {
		name   string
		mutate func(*RouteAuthorization)
	}{
		{
			name: "sub-millisecond",
			mutate: func(mutated *RouteAuthorization) {
				mutated.Claims.Route.ExpiresAt =
					mutated.Claims.Route.ExpiresAt.Add(
						time.Nanosecond,
					)
			},
		},
		{
			name: "alternate-timezone",
			mutate: func(mutated *RouteAuthorization) {
				mutated.Claims.Route.ExpiresAt =
					mutated.Claims.Route.ExpiresAt.In(
						time.FixedZone(
							"offset",
							60*60,
						),
					)
			},
		},
	}

	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			mutated := cloneRouteAuthorization(auth)
			mutation.mutate(&mutated)

			err := verifier.VerifyAndConsume(
				context.Background(),
				mutated,
				route,
				"wd_b",
			)
			if !errors.Is(
				err,
				ErrRouteAuthorizationInvalid,
			) {
				t.Fatalf(
					"VerifyAndConsume() error = %v, want invalid authorization",
					err,
				)
			}
		})
	}

	// Neither invalid representation was allowed to consume the JTI.
	// The original canonical authorization must still succeed.
	if err := verifier.VerifyAndConsume(
		context.Background(),
		auth,
		route,
		"wd_b",
	); err != nil {
		t.Fatalf(
			"canonical authorization failed after rejected mutations: %v",
			err,
		)
	}
}

func TestRouteAuthorizationVerifyAndConsume(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_000_000).UTC()
	route := routeAuthorizationTestRoute(now.Add(90 * time.Second))
	jti := routeAuthorizationTestJTI(1)

	claims := NewRouteAuthorizationClaims(
		route,
		"wd_b",
		jti,
		now,
	)
	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-1",
		claims,
	)
	if err != nil {
		t.Fatalf("SignRouteAuthorization() error: %v", err)
	}

	replay := NewMemoryRouteAuthorizationReplay()
	replay.now = func() time.Time { return now }

	verifier := RouteAuthorizationVerifier{
		KeyID:     "control-key-1",
		PublicKey: publicKey,
		Replay:    replay,
		Now:       func() time.Time { return now },
	}

	if err := verifier.VerifyAndConsume(
		context.Background(),
		auth,
		route,
		"wd_b",
	); err != nil {
		t.Fatalf("VerifyAndConsume() error: %v", err)
	}

	err = verifier.VerifyAndConsume(
		context.Background(),
		auth,
		route,
		"wd_b",
	)
	if !errors.Is(err, ErrRouteAuthorizationReplay) {
		t.Fatalf(
			"second VerifyAndConsume() error = %v, want replay",
			err,
		)
	}
}

func TestRouteAuthorizationReplayConsumptionIsAtomic(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_100_000).UTC()
	route := routeAuthorizationTestRoute(now.Add(90 * time.Second))
	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-1",
		NewRouteAuthorizationClaims(
			route,
			"wd_b",
			routeAuthorizationTestJTI(2),
			now,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	replay := NewMemoryRouteAuthorizationReplay()
	replay.now = func() time.Time { return now }

	verifier := RouteAuthorizationVerifier{
		KeyID:     "control-key-1",
		PublicKey: publicKey,
		Replay:    replay,
		Now:       func() time.Time { return now },
	}

	const attempts = 64
	var successes atomic.Int32
	var replays atomic.Int32

	var wg sync.WaitGroup
	wg.Add(attempts)

	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()

			err := verifier.VerifyAndConsume(
				context.Background(),
				auth,
				route,
				"wd_b",
			)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrRouteAuthorizationReplay):
				replays.Add(1)
			default:
				t.Errorf("VerifyAndConsume() error: %v", err)
			}
		}()
	}

	wg.Wait()

	if successes.Load() != 1 {
		t.Fatalf("successes = %d, want 1", successes.Load())
	}
	if replays.Load() != attempts-1 {
		t.Fatalf(
			"replays = %d, want %d",
			replays.Load(),
			attempts-1,
		)
	}
}

func TestRouteAuthorizationRejectsTampering(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_200_000).UTC()
	route := routeAuthorizationTestRoute(now.Add(90 * time.Second))
	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-1",
		NewRouteAuthorizationClaims(
			route,
			"wd_b",
			routeAuthorizationTestJTI(3),
			now,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*RouteAuthorization)
	}{
		{
			name: "route-id",
			mutate: func(a *RouteAuthorization) {
				a.Claims.Route.ID = "other-route"
			},
		},
		{
			name: "source",
			mutate: func(a *RouteAuthorization) {
				a.Claims.Route.Source = "wd_x"
			},
		},
		{
			name: "router",
			mutate: func(a *RouteAuthorization) {
				a.Claims.Router = "wd_x"
				a.Claims.Route.Hops[0].To = "wd_x"
				a.Claims.Route.Hops[1].From = "wd_x"
			},
		},
		{
			name: "destination",
			mutate: func(a *RouteAuthorization) {
				a.Claims.Route.Destination = "wd_x"
				a.Claims.Route.Hops[1].To = "wd_x"
			},
		},
		{
			name: "transport",
			mutate: func(a *RouteAuthorization) {
				a.Claims.Route.Hops[1].Transport = TransportLAN
			},
		},
		{
			name: "cost",
			mutate: func(a *RouteAuthorization) {
				a.Claims.Route.Hops[1].Cost++
			},
		},
		{
			name: "expiry",
			mutate: func(a *RouteAuthorization) {
				a.Claims.ExpiresUnixMS--
				a.Claims.Route.ExpiresAt =
					a.Claims.Route.ExpiresAt.Add(-time.Millisecond)
			},
		},
		{
			name: "jti",
			mutate: func(a *RouteAuthorization) {
				a.Claims.JTI = routeAuthorizationTestJTI(4)
			},
		},
		{
			name: "permission",
			mutate: func(a *RouteAuthorization) {
				a.Claims.Permission = "terminal.connect"
			},
		},
		{
			name: "key-id",
			mutate: func(a *RouteAuthorization) {
				a.KeyID = "control-key-2"
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			changed := cloneRouteAuthorization(auth)
			tc.mutate(&changed)

			replay := NewMemoryRouteAuthorizationReplay()
			replay.now = func() time.Time { return now }

			verifier := RouteAuthorizationVerifier{
				KeyID:     "control-key-1",
				PublicKey: publicKey,
				Replay:    replay,
				Now:       func() time.Time { return now },
			}

			if err := verifier.VerifyAndConsume(
				context.Background(),
				changed,
				route,
				"wd_b",
			); err == nil {
				t.Fatal("tampered authorization accepted")
			}
		})
	}
}

func TestRouteAuthorizationRejectsWrongVerificationKey(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_300_000).UTC()
	route := routeAuthorizationTestRoute(now.Add(90 * time.Second))
	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-1",
		NewRouteAuthorizationClaims(
			route,
			"wd_b",
			routeAuthorizationTestJTI(5),
			now,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	verifier := RouteAuthorizationVerifier{
		KeyID:     "control-key-1",
		PublicKey: wrongPublicKey,
		Replay:    NewMemoryRouteAuthorizationReplay(),
		Now:       func() time.Time { return now },
	}

	err = verifier.VerifyAndConsume(
		context.Background(),
		auth,
		route,
		"wd_b",
	)
	if !errors.Is(err, ErrRouteAuthorizationSignature) {
		t.Fatalf(
			"VerifyAndConsume() error = %v, want signature failure",
			err,
		)
	}
}

func TestRouteAuthorizationRejectsExpiredAndLongLived(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_400_000).UTC()

	t.Run("expired", func(t *testing.T) {
		issuedAt := now.Add(-90 * time.Second)
		route := routeAuthorizationTestRoute(now.Add(-time.Millisecond))

		claims := NewRouteAuthorizationClaims(
			route,
			"wd_b",
			routeAuthorizationTestJTI(6),
			issuedAt,
		)
		auth, err := SignRouteAuthorization(
			privateKey,
			"control-key-1",
			claims,
		)
		if err != nil {
			t.Fatal(err)
		}

		verifier := RouteAuthorizationVerifier{
			KeyID:     "control-key-1",
			PublicKey: publicKey,
			Replay:    NewMemoryRouteAuthorizationReplay(),
			Now:       func() time.Time { return now },
		}

		err = verifier.VerifyAndConsume(
			context.Background(),
			auth,
			route,
			"wd_b",
		)
		if !errors.Is(err, ErrRouteAuthorizationExpired) {
			t.Fatalf(
				"VerifyAndConsume() error = %v, want expired",
				err,
			)
		}
	})

	t.Run("over-max-lifetime", func(t *testing.T) {
		route := routeAuthorizationTestRoute(
			now.Add(MaxRouteAuthorizationLifetime + time.Second),
		)

		_, err := SignRouteAuthorization(
			privateKey,
			"control-key-1",
			NewRouteAuthorizationClaims(
				route,
				"wd_b",
				routeAuthorizationTestJTI(7),
				now,
			),
		)
		if !errors.Is(err, ErrRouteAuthorizationInvalid) {
			t.Fatalf(
				"SignRouteAuthorization() error = %v, want invalid",
				err,
			)
		}
	})
}

func TestRouteAuthorizationRejectsFutureIssueTime(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_500_000).UTC()
	route := routeAuthorizationTestRoute(now.Add(90 * time.Second))
	claims := NewRouteAuthorizationClaims(
		route,
		"wd_b",
		routeAuthorizationTestJTI(8),
		now.Add(time.Second),
	)
	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-1",
		claims,
	)
	if err != nil {
		t.Fatal(err)
	}

	verifier := RouteAuthorizationVerifier{
		KeyID:     "control-key-1",
		PublicKey: publicKey,
		Replay:    NewMemoryRouteAuthorizationReplay(),
		Now:       func() time.Time { return now },
	}

	err = verifier.VerifyAndConsume(
		context.Background(),
		auth,
		route,
		"wd_b",
	)
	if !errors.Is(err, ErrRouteAuthorizationNotYetValid) {
		t.Fatalf(
			"VerifyAndConsume() error = %v, want not-yet-valid",
			err,
		)
	}
}

func TestRouteAuthorizationMismatchDoesNotConsumeJTI(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_600_000).UTC()
	route := routeAuthorizationTestRoute(now.Add(90 * time.Second))
	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-1",
		NewRouteAuthorizationClaims(
			route,
			"wd_b",
			routeAuthorizationTestJTI(9),
			now,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	replay := NewMemoryRouteAuthorizationReplay()
	replay.now = func() time.Time { return now }

	verifier := RouteAuthorizationVerifier{
		KeyID:     "control-key-1",
		PublicKey: publicKey,
		Replay:    replay,
		Now:       func() time.Time { return now },
	}

	wrongRoute := cloneAuthorizationRoute(route)
	wrongRoute.Hops[1].Cost++

	err = verifier.VerifyAndConsume(
		context.Background(),
		auth,
		wrongRoute,
		"wd_b",
	)
	if !errors.Is(err, ErrRouteAuthorizationMismatch) {
		t.Fatalf(
			"wrong-route error = %v, want mismatch",
			err,
		)
	}

	if err := verifier.VerifyAndConsume(
		context.Background(),
		auth,
		route,
		"wd_b",
	); err != nil {
		t.Fatalf(
			"correct verification after mismatch error: %v",
			err,
		)
	}
}

func TestRouteAuthorizationSigningOwnsRouteCopy(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_700_000).UTC()
	route := routeAuthorizationTestRoute(now.Add(90 * time.Second))
	claims := NewRouteAuthorizationClaims(
		route,
		"wd_b",
		routeAuthorizationTestJTI(10),
		now,
	)

	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-1",
		claims,
	)
	if err != nil {
		t.Fatal(err)
	}

	claims.Route.Hops[0].Transport = TransportBluetooth
	route.Hops[0].Transport = TransportBluetooth

	expectedRoute := routeAuthorizationTestRoute(now.Add(90 * time.Second))
	replay := NewMemoryRouteAuthorizationReplay()
	replay.now = func() time.Time { return now }

	verifier := RouteAuthorizationVerifier{
		KeyID:     "control-key-1",
		PublicKey: publicKey,
		Replay:    replay,
		Now:       func() time.Time { return now },
	}

	if err := verifier.VerifyAndConsume(
		context.Background(),
		auth,
		expectedRoute,
		"wd_b",
	); err != nil {
		t.Fatalf("authorization changed through aliased route: %v", err)
	}
}

func TestRouteAuthorizationRequiresReplayProtection(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(1_800_000_800_000).UTC()
	route := routeAuthorizationTestRoute(now.Add(90 * time.Second))
	auth, err := SignRouteAuthorization(
		privateKey,
		"control-key-1",
		NewRouteAuthorizationClaims(
			route,
			"wd_b",
			routeAuthorizationTestJTI(11),
			now,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	verifier := RouteAuthorizationVerifier{
		KeyID:     "control-key-1",
		PublicKey: publicKey,
		Now:       func() time.Time { return now },
	}

	err = verifier.VerifyAndConsume(
		context.Background(),
		auth,
		route,
		"wd_b",
	)
	if !errors.Is(err, ErrRouteAuthorizationReplayMissing) {
		t.Fatalf(
			"VerifyAndConsume() error = %v, want replay protection required",
			err,
		)
	}
}

func routeAuthorizationTestRoute(expiresAt time.Time) Route {
	return Route{
		ID:          "route-a-b-c",
		Source:      "wd_a",
		Destination: "wd_c",
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
		ExpiresAt: expiresAt,
	}
}

func routeAuthorizationTestJTI(last byte) string {
	var raw [16]byte
	raw[15] = last
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

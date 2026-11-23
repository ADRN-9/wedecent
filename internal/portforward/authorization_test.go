package portforward

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

const (
	testInitiator   = mesh.DeviceID("wd_aaaaaaaaaaaaaaaa")
	testDestination = mesh.DeviceID("wd_bbbbbbbbbbbbbbbb")
	testRouter      = mesh.DeviceID("wd_cccccccccccccccc")
)

func testClaims(now time.Time, direction Direction) Claims {
	source, destination := testInitiator, testDestination
	if direction == DirectionRemote {
		source, destination = testDestination, testInitiator
	}
	expires := now.Add(90 * time.Second).UTC().Truncate(time.Millisecond)
	return Claims{
		Version:           AuthorizationVersion,
		Issuer:            AuthorizationIssuer,
		Audience:          AuthorizationAudience,
		Permission:        PermissionLocal,
		JTI:               base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
		ForwardingID:      "00000000-0000-4000-8000-000000000001",
		Direction:         direction,
		InitiatingDevice:  testInitiator,
		DestinationDevice: testDestination,
		Route: mesh.Route{
			ID:          "00000000-0000-4000-8000-000000000002",
			Source:      source,
			Destination: destination,
			Hops:        []mesh.RouteHop{{From: source, To: destination, Transport: mesh.TransportName("internet"), Cost: 12}},
			ExpiresAt:   expires,
		},
		DestinationAddress: "example.com",
		DestinationPort:    443,
		Listener:           DefaultListenerPolicy(43123),
		Protocol:           ProtocolTCP,
		IssuedAtUnixMS:     now.UnixMilli(),
		ExpiresAtUnixMS:    expires.UnixMilli(),
		Limits:             ResourceLimits{MaxConnections: 4, MaxDurationSeconds: 120, IdleTimeoutSeconds: 30},
	}
}

func testRoutedClaims(now time.Time, direction Direction) Claims {
	claims := testClaims(now, direction)
	source, destination := claims.Route.Source, claims.Route.Destination
	claims.Router = testRouter
	claims.Route.Hops = []mesh.RouteHop{
		{From: source, To: testRouter, Transport: mesh.TransportName("internet"), Cost: 12},
		{From: testRouter, To: destination, Transport: mesh.TransportName("internet"), Cost: 13},
	}
	return claims
}

func testRouteAuthorization(t *testing.T, claims Claims) (mesh.RouteAuthorization, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jti, err := mesh.NewRouteAuthorizationJTI()
	if err != nil {
		t.Fatal(err)
	}
	routeClaims := mesh.NewRouteAuthorizationClaims(
		claims.Route,
		claims.Router,
		jti,
		time.UnixMilli(claims.IssuedAtUnixMS),
	)
	authorization, err := mesh.SignRouteAuthorization(privateKey, "route-key-1", routeClaims)
	if err != nil {
		t.Fatal(err)
	}
	return authorization, publicKey
}

func TestPortForwardRequiresIndependentRouteAuthorization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testRoutedClaims(now, DirectionLocal)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := SignAuthorization(privateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRouteAuthorizationBinding(auth); !errors.Is(err, ErrRouteAuthorizationRequired) {
		t.Fatalf("missing route authorization error = %v", err)
	}

	routeAuth, routePublicKey := testRouteAuthorization(t, claims)
	auth.RouteAuthorization = routeAuth
	if err := ValidateRouteAuthorizationBinding(auth); err != nil {
		t.Fatalf("valid independent route authorization rejected: %v", err)
	}
	routeVerifier := mesh.RouteAuthorizationVerifier{
		KeyID:     "route-key-1",
		PublicKey: routePublicKey,
		Replay:    mesh.NewMemoryRouteAuthorizationReplay(),
		Now:       func() time.Time { return now },
	}
	if err := routeVerifier.VerifyAndConsume(context.Background(), routeAuth, claims.Route, claims.Router); err != nil {
		t.Fatalf("routing trust-domain verification failed: %v", err)
	}

	changed := cloneAuthorization(auth)
	changed.RouteAuthorization.Claims.Route.Hops[0].Cost++
	if err := ValidateRouteAuthorizationBinding(changed); !errors.Is(err, ErrRouteAuthorizationMismatch) {
		t.Fatalf("mismatched route authorization error = %v", err)
	}
	changed = cloneAuthorization(auth)
	changed.RouteAuthorization.Signature = "invalid"
	if err := routeVerifier.VerifyAndConsume(context.Background(), changed.RouteAuthorization, claims.Route, claims.Router); !errors.Is(err, mesh.ErrRouteAuthorizationSignature) {
		t.Fatalf("tampered route signature error = %v", err)
	}
}

func TestAuthorizationRejectsMissingCapability(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	replay := NewMemoryReplay(8)
	replay.Now = func() time.Time { return now }
	verifier := AuthorizationVerifier{
		PublicKey: publicKey,
		Replay:    replay,
		Now:       func() time.Time { return now },
	}
	if _, err := verifier.VerifyAndConsume(context.Background(), Authorization{}); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("missing authorization error = %v", err)
	}
	if len(replay.used) != 0 {
		t.Fatal("missing authorization changed replay state")
	}
}

func TestAuthorizationSignVerifyAndReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, err := SignAuthorization(privateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	wantKeyID, err := AuthorizationKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if auth.KeyID != wantKeyID {
		t.Fatalf("key ID = %q, want %q", auth.KeyID, wantKeyID)
	}
	replay := NewMemoryReplay(16)
	replay.Now = func() time.Time { return now }
	verifier := AuthorizationVerifier{PublicKey: publicKey, Replay: replay, Now: func() time.Time { return now }}
	got, err := verifier.VerifyAndConsume(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if got.ForwardingID != claims.ForwardingID || got.Direction != DirectionLocal {
		t.Fatalf("claims = %#v", got)
	}
	if _, err := verifier.VerifyAndConsume(context.Background(), auth); !errors.Is(err, ErrAuthorizationReplay) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestAuthorizationRejectsTamperingAndDoesNotConsumeValidCapability(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	auth, err := SignAuthorization(privateKey, testClaims(now, DirectionLocal))
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Authorization){
		func(a *Authorization) { a.Claims.Direction = DirectionRemote },
		func(a *Authorization) { a.Claims.DestinationPort++ },
		func(a *Authorization) { a.Claims.Listener.Port++ },
		func(a *Authorization) { a.Claims.Listener.Address = "0.0.0.0" },
		func(a *Authorization) { a.Claims.Route.Hops[0].Cost++ },
		func(a *Authorization) { a.Claims.DestinationDevice = testRouter },
	}
	for i, mutate := range mutations {
		changed := auth
		changed.Claims = cloneClaims(auth.Claims)
		mutate(&changed)
		replay := NewMemoryReplay(16)
		replay.Now = func() time.Time { return now }
		verifier := AuthorizationVerifier{PublicKey: publicKey, Replay: replay, Now: func() time.Time { return now }}
		if _, err := verifier.VerifyAndConsume(context.Background(), changed); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
		if _, err := verifier.VerifyAndConsume(context.Background(), auth); err != nil {
			t.Fatalf("mutation consumed valid JTI: %v", err)
		}
	}
}

func TestAuthorizationBindsRemoteDirectionAndListenerDevice(t *testing.T) {
	claims := testClaims(time.Now().UTC().Truncate(time.Millisecond), DirectionRemote)
	claims.Permission = PermissionRemote
	if err := ValidateClaims(claims); err != nil {
		t.Fatal(err)
	}
	if ListenerDevice(claims) != testDestination {
		t.Fatalf("listener device = %q", ListenerDevice(claims))
	}
	claims.Route.Source, claims.Route.Destination = testInitiator, testDestination
	if err := ValidateClaims(claims); err == nil {
		t.Fatal("incorrect remote route accepted")
	}
}

func TestAuthorizationRejectsUnsafeOrMalformedClaims(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	base := testClaims(now, DirectionLocal)
	mutations := []func(*Claims){
		func(c *Claims) { c.ForwardingID = "" },
		func(c *Claims) { c.Permission = PermissionRemote },
		func(c *Claims) { c.DestinationPort = 0 },
		func(c *Claims) { c.DestinationAddress = "::ffff:127.0.0.1" },
		func(c *Claims) { c.Listener.Address = "0.0.0.0" },
		func(c *Claims) { c.Listener.Address = "1.1.1.1" },
		func(c *Claims) { c.ExpiresAtUnixMS = c.IssuedAtUnixMS + MaxAuthorizationLifetime.Milliseconds() + 1 },
		func(c *Claims) { c.Route.ExpiresAt = c.Route.ExpiresAt.Add(time.Millisecond) },
	}
	for i, mutate := range mutations {
		claims := cloneClaims(base)
		mutate(&claims)
		if err := ValidateClaims(claims); err == nil {
			t.Fatalf("unsafe claim mutation %d accepted", i)
		}
	}
}

type mismatchedSigner struct {
	signer ed25519.PrivateKey
	public ed25519.PublicKey
}

func (s mismatchedSigner) Public() crypto.PublicKey { return s.public }
func (s mismatchedSigner) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signer.Sign(random, message, opts)
}

func TestSignerMustMatchSeparatelySuppliedPublicMaterial(t *testing.T) {
	_, first, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignAuthorization(mismatchedSigner{signer: first, public: secondPublic}, testClaims(time.Now().UTC().Truncate(time.Millisecond), DirectionLocal)); !errors.Is(err, ErrAuthorizationSignature) {
		t.Fatalf("mismatched signer error = %v", err)
	}
}

func TestAuthorizationReplayConsumptionIsAtomic(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	auth, err := SignAuthorization(privateKey, testClaims(now, DirectionLocal))
	if err != nil {
		t.Fatal(err)
	}
	replay := NewMemoryReplay(128)
	replay.Now = func() time.Time { return now }
	verifier := AuthorizationVerifier{PublicKey: publicKey, Replay: replay, Now: func() time.Time { return now }}
	var successes, replays atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := verifier.VerifyAndConsume(context.Background(), auth)
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, ErrAuthorizationReplay) {
				replays.Add(1)
			} else {
				t.Errorf("verify: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || replays.Load() != 63 {
		t.Fatalf("successes=%d replays=%d", successes.Load(), replays.Load())
	}
}

func TestAuthorizationRejectsExpiredAndFutureCapabilities(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	replay := NewMemoryReplay(8)
	replay.Now = func() time.Time { return now }
	verifier := AuthorizationVerifier{
		PublicKey: publicKey,
		Replay:    replay,
		Now:       func() time.Time { return now },
	}

	expiredClaims := testClaims(now, DirectionLocal)
	expiredAuth, err := SignAuthorization(privateKey, expiredClaims)
	if err != nil {
		t.Fatal(err)
	}
	verifier.Now = func() time.Time { return time.UnixMilli(expiredClaims.ExpiresAtUnixMS + 1) }
	if _, err := verifier.VerifyAndConsume(context.Background(), expiredAuth); !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("expired capability error = %v", err)
	}

	futureClaims := testClaims(now, DirectionLocal)
	futureClaims.IssuedAtUnixMS = now.Add(time.Minute).UnixMilli()
	futureAuth, err := SignAuthorization(privateKey, futureClaims)
	if err != nil {
		t.Fatal(err)
	}
	verifier.Now = func() time.Time { return now }
	if _, err := verifier.VerifyAndConsume(context.Background(), futureAuth); !errors.Is(err, ErrAuthorizationNotYetValid) {
		t.Fatalf("future capability error = %v", err)
	}
}

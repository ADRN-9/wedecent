package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type destinationTestResolver struct {
	addresses []netip.Addr
	calls     int
}

func (r *destinationTestResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.calls++
	if network != "ip" || host != "example.com" {
		return nil, ErrDestinationResolution
	}
	return append([]netip.Addr(nil), r.addresses...), nil
}

type destinationTestDialer struct {
	mu        sync.Mutex
	addresses []string
	opened    chan net.Conn
}

func (d *destinationTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp" {
		return nil, ErrDestinationDenied
	}
	local, remote := net.Pipe()
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.mu.Unlock()
	if d.opened != nil {
		select {
		case d.opened <- remote:
		case <-ctx.Done():
			_ = local.Close()
			_ = remote.Close()
			return nil, ctx.Err()
		}
	} else {
		_ = remote.Close()
	}
	return local, nil
}

func (d *destinationTestDialer) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addresses...)
}

func newDestinationTestConfig(t *testing.T, now time.Time, publicKey ed25519.PublicKey) (DestinationConfig, *MemoryReplay, *destinationTestDialer, *memoryAudit) {
	t.Helper()
	replay := NewMemoryReplay(16)
	replay.Now = func() time.Time { return now }
	dialer := &destinationTestDialer{opened: make(chan net.Conn, 8)}
	log := &memoryAudit{}
	return DestinationConfig{
		LocalDeviceID:        testDestination,
		AuthenticatedPeerID:  testInitiator,
		Verifier:             AuthorizationVerifier{PublicKey: publicKey, Replay: replay, Now: func() time.Time { return now }},
		PermissionAuthorizer: allowPortForwardPermission{},
		Resolver:             &destinationTestResolver{addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}},
		Dialer:               dialer,
		Policy:               DestinationPolicy{AllowPublic: true, AllowedPorts: []PortRange{{First: 443, Last: 443}}},
		Audit:                log,
		MaxConnections:       4,
		DialTimeout:          time.Second,
	}, replay, dialer, log
}

func signDestinationTestAuthorization(t *testing.T, claims Claims) (Authorization, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := SignAuthorization(privateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return auth, publicKey
}

func TestDestinationSessionAuthenticatesOnceAndMultiplexesChildConnections(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, replay, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	session, err := NewDestinationSession(context.Background(), cfg, auth)
	if err != nil {
		t.Fatal(err)
	}

	first, err := session.OpenChild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.OpenChild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.used) != 1 {
		t.Fatalf("parent authorization consumed %d times, want exactly once", len(replay.used))
	}
	if got := dialer.snapshot(); len(got) != 2 || got[0] != "93.184.216.34:443" || got[1] != "93.184.216.34:443" {
		t.Fatalf("destination dials = %v, want two pinned-IP dials", got)
	}

	firstRemote := <-dialer.opened
	secondRemote := <-dialer.opened
	if _, err := first.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	firstBytes := make([]byte, 5)
	if _, err := io.ReadFull(firstRemote, firstBytes); err != nil || string(firstBytes) != "first" {
		t.Fatalf("first child payload = %q, error = %v", firstBytes, err)
	}
	if _, err := second.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	secondBytes := make([]byte, 6)
	if _, err := io.ReadFull(secondRemote, secondBytes); err != nil || string(secondBytes) != "second" {
		t.Fatalf("second child payload = %q, error = %v", secondBytes, err)
	}

	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	_ = firstRemote.Close()
	_ = secondRemote.Close()
	if _, err := first.Write([]byte("after-close")); err == nil {
		t.Fatal("first child remained writable after parent session close")
	}
}

func TestDestinationSessionRejectsWrongDeviceIdentityBeforeReplayConsumption(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, replay, _, _ := newDestinationTestConfig(t, now, publicKey)
	cfg.LocalDeviceID = testInitiator
	if _, err := NewDestinationSession(context.Background(), cfg, auth); !errors.Is(err, ErrWrongDestinationDevice) {
		t.Fatalf("wrong destination identity error = %v", err)
	}
	if len(replay.used) != 0 {
		t.Fatal("wrong destination identity consumed the capability")
	}

	cfg.LocalDeviceID = testDestination
	cfg.AuthenticatedPeerID = testRouter
	if _, err := NewDestinationSession(context.Background(), cfg, auth); !errors.Is(err, ErrAuthorizationMismatch) {
		t.Fatalf("wrong authenticated peer error = %v", err)
	}
	if len(replay.used) != 0 {
		t.Fatal("wrong peer identity consumed the capability")
	}
}

func TestDestinationSessionRejectsPermissionAndDestinationPolicyBeforeDial(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, replay, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	cfg.PermissionAuthorizer = grantPortForwardPermission{permission: PermissionRemote}
	if _, err := NewDestinationSession(context.Background(), cfg, auth); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("destination permission error = %v", err)
	}
	if len(dialer.snapshot()) != 0 || len(replay.used) != 1 {
		t.Fatal("permission denial dialed destination or failed to consume authorization")
	}

	claims = testClaims(now, DirectionLocal)
	auth, publicKey = signDestinationTestAuthorization(t, claims)
	cfg, replay, dialer, _ = newDestinationTestConfig(t, now, publicKey)
	cfg.Policy.AllowedPorts = []PortRange{{First: 8443, Last: 8443}}
	if _, err := NewDestinationSession(context.Background(), cfg, auth); !errors.Is(err, ErrDestinationDenied) {
		t.Fatalf("unauthorized destination port error = %v", err)
	}
	if len(dialer.snapshot()) != 0 || len(replay.used) != 1 {
		t.Fatal("unauthorized destination was dialed or capability was not consumed")
	}
}

func TestDestinationSessionRequiresSeparateRouteAuthorization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testRoutedClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, replay, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	cfg.AuthenticatedPeerID = testRouter
	if _, err := NewDestinationSession(context.Background(), cfg, auth); !errors.Is(err, ErrRouteAuthorizationRequired) {
		t.Fatalf("missing route authorization error = %v", err)
	}
	if len(replay.used) != 1 || len(dialer.snapshot()) != 0 {
		t.Fatal("missing route authorization did not fail closed")
	}
}

func TestDestinationSessionBoundsChildrenAndExpiresActiveStreams(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.Limits.MaxConnections = 2
	claims.Limits.MaxDurationSeconds = 2
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, _, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	cfg.MaxConnections = 1
	session, err := NewDestinationSession(context.Background(), cfg, auth)
	if err != nil {
		t.Fatal(err)
	}
	child, err := session.OpenChild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.OpenChild(context.Background()); !errors.Is(err, ErrForwardLimit) {
		t.Fatalf("over-limit child error = %v", err)
	}
	remote := <-dialer.opened
	_ = remote
	select {
	case <-session.ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("destination session did not expire at its signed duration")
	}
	if _, err := child.Write([]byte("after-expiry")); err == nil {
		t.Fatal("child remained writable after destination session expiry")
	}
	_ = child.Close()
}

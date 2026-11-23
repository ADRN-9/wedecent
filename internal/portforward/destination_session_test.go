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

	"wedecent.com/wedecent/internal/audit"
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

type destinationTestTrust struct {
	mu      sync.RWMutex
	trusted map[string]bool
	err     error
}

func (t *destinationTestTrust) IsTrusted(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.err != nil {
		return false, t.err
	}
	return t.trusted[id], nil
}

func (t *destinationTestTrust) revoke(id string) {
	t.mu.Lock()
	delete(t.trusted, id)
	t.mu.Unlock()
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
		TrustChecker:         &destinationTestTrust{trusted: map[string]bool{string(testInitiator): true}},
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
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := session.OpenChild(context.Background())
	if err != nil {
		t.Fatalf("sequential child stream was not admitted: %v", err)
	}
	thirdRemote := <-dialer.opened
	if _, err := third.Write([]byte("third")); err != nil {
		t.Fatal(err)
	}
	thirdBytes := make([]byte, 5)
	if _, err := io.ReadFull(thirdRemote, thirdBytes); err != nil || string(thirdBytes) != "third" {
		t.Fatalf("third child payload = %q, error = %v", thirdBytes, err)
	}
	if len(replay.used) != 1 || len(dialer.snapshot()) != 3 {
		t.Fatal("sequential child stream re-consumed the parent capability or skipped pinned dialing")
	}

	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	_ = firstRemote.Close()
	_ = secondRemote.Close()
	_ = thirdRemote.Close()
	if _, err := third.Write([]byte("after-close")); err == nil {
		t.Fatal("third child remained writable after parent session close")
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

func TestDestinationSessionRejectsUntrustedAuthenticatedPeerBeforeReplayConsumption(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, replay, _, _ := newDestinationTestConfig(t, now, publicKey)
	cfg.TrustChecker = &destinationTestTrust{trusted: map[string]bool{}}
	if _, err := NewDestinationSession(context.Background(), cfg, auth); !errors.Is(err, ErrPeerNotTrusted) {
		t.Fatalf("untrusted authenticated peer error = %v", err)
	}
	if len(replay.used) != 0 {
		t.Fatal("untrusted peer consumed the forwarding capability")
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
	cfg.AuthenticatedRouterID = testRouter
	cfg.RouterTrustChecker = &destinationTestTrust{trusted: map[string]bool{string(testRouter): true}}
	if _, err := NewDestinationSession(context.Background(), cfg, auth); !errors.Is(err, ErrRouteAuthorizationRequired) {
		t.Fatalf("missing route authorization error = %v", err)
	}
	if len(replay.used) != 0 || len(dialer.snapshot()) != 0 {
		t.Fatal("missing route authorization consumed a grant or dialed a destination")
	}
}

func TestDestinationSessionDoesNotLetTrustedRouterImpersonateInitiator(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testRoutedClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	auth.RouteAuthorization, _ = testRouteAuthorization(t, claims)

	cfg, replay, _, _ := newDestinationTestConfig(t, now, publicKey)
	cfg.AuthenticatedPeerID = testRouter
	cfg.AuthenticatedRouterID = testRouter
	cfg.TrustChecker = &destinationTestTrust{trusted: map[string]bool{string(testRouter): true}}
	cfg.RouterTrustChecker = &destinationTestTrust{trusted: map[string]bool{string(testRouter): true}}
	if _, err := NewDestinationSession(context.Background(), cfg, auth); !errors.Is(err, ErrAuthorizationMismatch) {
		t.Fatalf("router impersonation error = %v, want endpoint identity mismatch", err)
	}
	if len(replay.used) != 0 {
		t.Fatal("trusted router consumed the endpoint forwarding capability")
	}

	cfg.AuthenticatedPeerID = testInitiator
	cfg.TrustChecker = &destinationTestTrust{trusted: map[string]bool{string(testInitiator): true}}
	session, err := NewDestinationSession(context.Background(), cfg, auth)
	if err != nil {
		t.Fatalf("separately authenticated endpoint and router rejected: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDestinationSessionRequiresRouterTrustSeparately(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testRoutedClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	auth.RouteAuthorization, _ = testRouteAuthorization(t, claims)
	cfg, replay, _, _ := newDestinationTestConfig(t, now, publicKey)
	cfg.AuthenticatedRouterID = testRouter
	cfg.RouterTrustChecker = &destinationTestTrust{trusted: map[string]bool{}}
	if _, err := NewDestinationSession(context.Background(), cfg, auth); !errors.Is(err, ErrRouterNotTrusted) {
		t.Fatalf("untrusted router error = %v", err)
	}
	if len(replay.used) != 0 {
		t.Fatal("untrusted router consumed the endpoint forwarding capability")
	}
}

func TestDestinationSessionTrustRevocationClosesChildStreams(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, _, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	trustChecker := &destinationTestTrust{trusted: map[string]bool{string(testInitiator): true}}
	cfg.TrustChecker = trustChecker
	cfg.TrustPollInterval = 20 * time.Millisecond
	session, err := NewDestinationSession(context.Background(), cfg, auth)
	if err != nil {
		t.Fatal(err)
	}
	child, err := session.OpenChild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	remote := <-dialer.opened
	trustChecker.revoke(string(testInitiator))
	select {
	case <-session.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("destination session did not close after peer trust revocation")
	}
	if _, err := child.Write([]byte("after-revocation")); err == nil {
		t.Fatal("child stream remained writable after peer trust revocation")
	}
	_ = remote.Close()
}

func TestDestinationSessionRouterTrustRevocationClosesChildren(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testRoutedClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	auth.RouteAuthorization, _ = testRouteAuthorization(t, claims)
	cfg, _, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	routerTrust := &destinationTestTrust{trusted: map[string]bool{string(testRouter): true}}
	cfg.AuthenticatedRouterID = testRouter
	cfg.RouterTrustChecker = routerTrust
	session, err := NewDestinationSession(context.Background(), cfg, auth)
	if err != nil {
		t.Fatal(err)
	}
	child, err := session.OpenChild(context.Background())
	if err != nil {
		_ = session.Close()
		t.Fatal(err)
	}
	remote := <-dialer.opened
	defer remote.Close()
	routerTrust.revoke(string(testRouter))
	select {
	case <-session.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("destination session did not close after router trust revocation")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := child.Write([]byte("after-router-revocation")); err == nil {
		t.Fatal("child remained writable after router trust revocation")
	}
}

func TestDestinationSessionParentCancellationClosesChildren(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, _, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	parentCtx, cancelParent := context.WithCancel(context.Background())
	session, err := NewDestinationSession(parentCtx, cfg, auth)
	if err != nil {
		cancelParent()
		t.Fatal(err)
	}
	child, err := session.OpenChild(context.Background())
	if err != nil {
		cancelParent()
		t.Fatal(err)
	}
	remote := <-dialer.opened
	defer remote.Close()
	cancelParent()
	select {
	case <-session.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("destination child/session did not terminate after authenticated parent cancellation")
	}
	if _, err := child.Write([]byte("after-parent-cancel")); err == nil {
		t.Fatal("child remained writable after authenticated parent cancellation")
	}
}

func TestDestinationSessionIdleWatchClosesAnActuallyIdleChild(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, _, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	session, err := NewDestinationSession(context.Background(), cfg, auth)
	if err != nil {
		t.Fatal(err)
	}
	session.idleTimeout = 60 * time.Millisecond
	child, err := session.OpenChild(context.Background())
	if err != nil {
		_ = session.Close()
		t.Fatal(err)
	}
	remote := <-dialer.opened
	defer remote.Close()
	readDone := make(chan error, 1)
	go func() {
		_, err := child.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("idle child read unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		_ = session.Close()
		t.Fatal("idle child was not closed by the destination-side idle timer")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDestinationChildCloseWriteDoesNotCloseConnectionWhenUnsupported(t *testing.T) {
	left, right := net.Pipe()
	session := &DestinationSession{
		claims: testClaims(time.Now().UTC(), DirectionLocal),
		localID: testDestination,
		peerID: testInitiator,
		audit: &memoryAudit{},
		children: make(map[uint64]*destinationChildConn),
	}
	child := &destinationChildConn{Conn: newIdleConn(left, time.Second), session: session, id: 1}
	session.children[1] = child
	if err := child.CloseWrite(); !errors.Is(err, ErrHalfCloseUnsupported) {
		t.Fatalf("unsupported half-close error = %v", err)
	}
	if _, err := child.Write([]byte("still-open")); err != nil {
		t.Fatalf("unsupported half-close destroyed the connection: %v", err)
	}
	_ = child.Close()
	_ = right.Close()
}

func TestDestinationSessionAppliesSignedIdleTimeoutToEveryChild(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.Limits.IdleTimeoutSeconds = 5
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, _, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	session, err := NewDestinationSession(context.Background(), cfg, auth)
	if err != nil {
		t.Fatal(err)
	}
	child, err := session.OpenChild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = <-dialer.opened
	idle, ok := child.Conn.(idleConn)
	if !ok || idle.idle != 5*time.Second {
		t.Fatalf("destination child idle policy = %#v, want signed 5s idle timeout", child.Conn)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

type destinationCloseErrorConn struct {
	net.Conn
}

func (c destinationCloseErrorConn) Close() error {
	_ = c.Conn.Close()
	return errors.New("simulated child close failure")
}

func TestDestinationChildCloseAuditReportsConnectionCloseFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auditLog := &memoryAudit{}
	left, right := net.Pipe()
	defer right.Close()
	session := &DestinationSession{
		claims:   claims,
		localID:  testDestination,
		peerID:   testInitiator,
		audit:    auditLog,
		children: make(map[uint64]*destinationChildConn),
	}
	child := &destinationChildConn{Conn: destinationCloseErrorConn{Conn: left}, session: session, id: 1}
	session.children[1] = child
	if err := child.Close(); err == nil {
		t.Fatal("connection close failure was hidden")
	}
	events := auditLog.snapshot()
	if len(events) != 1 || events[0].Type != "port_forward.destination_child_closed" ||
		events[0].Outcome != "failed" || events[0].Reason != "child_connection_close_failed" {
		t.Fatalf("child close audit = %#v, want failed closure", events)
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
	defer remote.Close()
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


type blockingDestinationAudit struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type waitCanceledDestinationDialer struct{}

func (waitCanceledDestinationDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (a *blockingDestinationAudit) Append(event audit.Event) error {
	if event.Type == "port_forward.destination_child" && event.Outcome == "attempt" {
		a.once.Do(func() {
			close(a.started)
			<-a.release
		})
	}
	return nil
}

func TestDestinationSessionCloseDoesNotWaitForPendingChildOpen(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, _, _, _ := newDestinationTestConfig(t, now, publicKey)
	cfg.Dialer = waitCanceledDestinationDialer{}
	auditLog := &blockingDestinationAudit{started: make(chan struct{}), release: make(chan struct{})}
	released := false
	defer func() {
		if !released {
			close(auditLog.release)
		}
	}()
	cfg.Audit = auditLog
	parentCtx, cancelParent := context.WithCancel(context.Background())
	session, err := NewDestinationSession(parentCtx, cfg, auth)
	if err != nil {
		t.Fatal(err)
	}

	openDone := make(chan error, 1)
	go func() {
		_, err := session.OpenChild(context.Background())
		openDone <- err
	}()
	select {
	case <-auditLog.started:
	case <-time.After(time.Second):
		t.Fatal("child open did not reach the blocked audit append")
	}

	cancelParent()
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation waited for an in-flight child open")
	}

	close(auditLog.release)
	released = true
	select {
	case err := <-openDone:
		if !errors.Is(err, ErrDestinationSessionClosed) && !errors.Is(err, context.Canceled) {
			t.Fatalf("late child open error = %v, want destination session closed or canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late child open did not self-clean after the audit append resumed")
	}
}


type destinationBlockingCloseConn struct {
	net.Conn
	started  chan struct{}
	release  chan struct{}
	returned chan struct{}
	once     sync.Once
}

func (c *destinationBlockingCloseConn) Close() error {
	c.once.Do(func() {
		close(c.started)
		<-c.release
		_ = c.Conn.Close()
		close(c.returned)
	})
	return nil
}

func TestDestinationSessionCloseBoundsBlockedChildClose(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	auth, publicKey := signDestinationTestAuthorization(t, claims)
	cfg, _, dialer, _ := newDestinationTestConfig(t, now, publicKey)
	session, err := NewDestinationSession(context.Background(), cfg, auth)
	if err != nil {
		t.Fatal(err)
	}
	childConn, err := session.OpenChild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	child := childConn.(*destinationChildConn)
	remote := <-dialer.opened
	blocked := &destinationBlockingCloseConn{
		Conn: child.Conn, started: make(chan struct{}),
		release: make(chan struct{}), returned: make(chan struct{}),
	}
	released := false
	defer func() {
		if !released {
			close(blocked.release)
		}
	}()
	child.Conn = blocked
	session.closeTimeout = 50 * time.Millisecond

	closeDone := make(chan error, 1)
	go func() { closeDone <- session.Close() }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("destination child close did not reach the blocking connection")
	}
	select {
	case err := <-closeDone:
		if err == nil {
			t.Fatal("destination session hid the blocked child cleanup timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("destination session close waited indefinitely for a blocked child close")
	}
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("destination session did not close after its bounded cleanup timeout")
	}

	close(blocked.release)
	released = true
	select {
	case <-blocked.returned:
	case <-time.After(time.Second):
		t.Fatal("blocked child close did not finish after release")
	}
	deadline := time.After(time.Second)
	for {
		session.mu.Lock()
		_, exists := session.children[child.id]
		session.mu.Unlock()
		if !exists {
			break
		}
		select {
		case <-deadline:
			t.Fatal("child close did not release its session registration")
		case <-time.After(time.Millisecond):
		}
	}
	_ = remote.Close()
}

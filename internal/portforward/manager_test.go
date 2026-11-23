package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/mesh"
)

type memoryAudit struct {
	mu          sync.Mutex
	events      []audit.Event
	failType    string
	failOutcome string
}

func (a *memoryAudit) Append(event audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if event.Type == a.failType && (a.failOutcome == "" || event.Outcome == a.failOutcome) {
		return errors.New("audit persistence unavailable")
	}
	a.events = append(a.events, event)
	return nil
}
func (a *memoryAudit) snapshot() []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Event(nil), a.events...)
}

type queueListener struct {
	addr     net.Addr
	incoming chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func newQueueListener() *queueListener {
	return &queueListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123}, incoming: make(chan net.Conn, 16), closed: make(chan struct{})}
}
func newQueueListenerAddress(ip string) *queueListener {
	listener := newQueueListener()
	listener.addr = &net.TCPAddr{IP: net.ParseIP(ip), Port: 43123}
	return listener
}
func (l *queueListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.incoming:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *queueListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *queueListener) Addr() net.Addr { return l.addr }
func (l *queueListener) inject(conn net.Conn) bool {
	select {
	case l.incoming <- conn:
		return true
	case <-l.closed:
		return false
	}
}

type pipeConnector struct {
	mu                sync.Mutex
	calls             int
	lastAuthorization Authorization
	opened            chan net.Conn
	block             <-chan struct{}
}

func (c *pipeConnector) Open(ctx context.Context, auth Authorization) (ForwardingSession, error) {
	c.mu.Lock()
	c.calls++
	c.lastAuthorization = cloneAuthorization(auth)
	c.mu.Unlock()
	if c.block != nil {
		select {
		case <-c.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &pipeForwardingSession{connector: c, children: make(map[net.Conn]struct{})}, nil
}

type pipeForwardingSession struct {
	connector *pipeConnector
	mu        sync.Mutex
	closed    bool
	children  map[net.Conn]struct{}
}

func (s *pipeForwardingSession) OpenChild(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	left, right := net.Pipe()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = left.Close()
		_ = right.Close()
		return nil, ErrManagerClosed
	}
	child := &pipeTrackedConn{Conn: left, session: s}
	s.children[child] = struct{}{}
	s.mu.Unlock()
	if s.connector.opened != nil {
		select {
		case s.connector.opened <- right:
		default:
			_ = right.Close()
		}
	} else {
		_ = right.Close()
	}
	return child, nil
}

type pipeTrackedConn struct {
	net.Conn
	session *pipeForwardingSession
	once    sync.Once
}

func (c *pipeTrackedConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.session.mu.Lock()
		delete(c.session.children, c)
		c.session.mu.Unlock()
	})
	return err
}

func (s *pipeForwardingSession) Close() error {
	s.mu.Lock()
	s.closed = true
	children := make([]net.Conn, 0, len(s.children))
	for child := range s.children {
		children = append(children, child)
	}
	s.children = make(map[net.Conn]struct{})
	s.mu.Unlock()
	for _, child := range children {
		_ = child.Close()
	}
	return nil
}
func (c *pipeConnector) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *pipeConnector) lastAuth() Authorization {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneAuthorization(c.lastAuthorization)
}

type allowPortForwardPermission struct{}

func (allowPortForwardPermission) AuthorizePortForward(_ context.Context, claims Claims) error {
	want := PermissionLocal
	if claims.Direction == DirectionRemote {
		want = PermissionRemote
	}
	if claims.Permission != want {
		return ErrPermissionDenied
	}
	return nil
}

type grantPortForwardPermission struct {
	permission string
}

func (a grantPortForwardPermission) AuthorizePortForward(_ context.Context, claims Claims) error {
	if claims.Permission != a.permission {
		return ErrPermissionDenied
	}
	return nil
}

type allowListenerAdmin struct {
	calls int
	err   error
}

func (a *allowListenerAdmin) AuthorizePortForwardListener(context.Context, Claims) error {
	a.calls++
	return a.err
}

func managerTestLimits() ManagerLimits {
	return ManagerLimits{MaxForwards: 8, MaxForwardsPerDevice: 4, MaxConnections: 8, MaxConnectionsPerDevice: 4, MaxConnectionsPerForward: 4, MaxDuration: 3 * time.Minute, IdleTimeout: 30 * time.Second, DialTimeout: time.Second}
}

type managerTestTrustChecker struct {
	trusted map[string]bool
}

func (t managerTestTrustChecker) IsTrusted(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return t.trusted[id], nil
}

func newManagerForTest(t *testing.T, local mesh.DeviceID, claims Claims, connector Connector, auditLog *memoryAudit, admin ListenerAuthorizer, listen func(string, string) (net.Listener, error)) (*Manager, Authorization, *queueListener) {
	return newManagerForTestWithPermission(t, local, claims, connector, auditLog, admin, allowPortForwardPermission{}, listen)
}

func newManagerForTestWithPermission(t *testing.T, local mesh.DeviceID, claims Claims, connector Connector, auditLog *memoryAudit, admin ListenerAuthorizer, permission PermissionAuthorizer, listen func(string, string) (net.Listener, error)) (*Manager, Authorization, *queueListener) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := SignAuthorization(privateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	replay := NewMemoryReplay(32)
	now := time.Now().UTC().Truncate(time.Millisecond)
	replay.Now = func() time.Time { return now }
	verifier := AuthorizationVerifier{PublicKey: publicKey, Replay: replay, Now: func() time.Time { return now }}
	listener := newQueueListener()
	if listen == nil {
		listen = func(network, address string) (net.Listener, error) {
			if network != "tcp" || address != "127.0.0.1:43123" && claims.Listener.Exposure == ExposureLoopback {
				t.Errorf("listen(%q,%q)", network, address)
			}
			return listener, nil
		}
	}
	if auditLog == nil {
		auditLog = &memoryAudit{}
	}
	peerID := remoteEndpointDevice(claims, local)
	trustedPeers := map[string]bool{string(peerID): true}
	trustedRouters := map[string]bool{string(testRouter): true}
	manager, err := NewManager(ManagerConfig{
		LocalDeviceID:        local,
		Verifier:             verifier,
		TrustChecker:         managerTestTrustChecker{trusted: trustedPeers},
		RouterTrustChecker:   managerTestTrustChecker{trusted: trustedRouters},
		PermissionAuthorizer: permission,
		Connector:            connector,
		ListenerAuthorizer:   admin,
		Audit:                auditLog,
		Limits:               managerTestLimits(),
		Listen:               listen,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager, auth, listener
}

type bridgeCloseErrorConn struct {
	net.Conn
}

func (c bridgeCloseErrorConn) Close() error {
	_ = c.Conn.Close()
	return errors.New("simulated transport close failure")
}

func TestBridgeReportsConnectionCloseFailures(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	_ = leftPeer.Close()
	_ = rightPeer.Close()
	err := bridge(context.Background(), bridgeCloseErrorConn{Conn: left}, bridgeCloseErrorConn{Conn: right}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "simulated transport close failure") {
		t.Fatalf("bridge close result = %v, want propagated close failure", err)
	}
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErr:
		_ = client.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = client.Close()
		t.Fatal("timed out creating TCP pair")
	}
	return nil, nil
}

func TestBridgePreservesTCPHalfCloseAndResponse(t *testing.T) {
	client, left := tcpPair(t)
	right, server := tcpPair(t)
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- bridge(ctx, left, right, 2*time.Second) }()

	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(server)
	if err != nil || string(request) != "request" {
		t.Fatalf("server request = %q, error = %v", request, err)
	}
	if _, err := server.Write([]byte("complete-response")); err != nil {
		t.Fatal(err)
	}
	if err := server.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "complete-response" {
		t.Fatalf("client response = %q, error = %v", response, err)
	}
	select {
	case err := <-bridgeDone:
		if err != nil {
			t.Fatalf("bridge after successful TCP half-close = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("bridge did not finish after both TCP half-closes")
	}
}

func TestBridgeRejectsUnsupportedHalfCloseWithoutSilentFallback(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	_ = leftPeer.Close()
	_ = rightPeer.Close()
	err := bridge(context.Background(), left, right, time.Second)
	if !errors.Is(err, ErrHalfCloseUnsupported) {
		t.Fatalf("bridge unsupported half-close error = %v, want ErrHalfCloseUnsupported", err)
	}
}

func TestIdleConnActivityInEitherDirectionResetsSharedIdleTimer(t *testing.T) {
	local, peer := net.Pipe()
	wrapped := newIdleConn(local, 120*time.Millisecond)
	defer wrapped.Close()
	defer peer.Close()

	peerReadDone := make(chan struct{})
	go func() {
		defer close(peerReadDone)
		buf := make([]byte, 1)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()
	readDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Read(make([]byte, 1))
		readDone <- err
	}()

	for i := 0; i < 5; i++ {
		if _, err := wrapped.Write([]byte("x")); err != nil {
			t.Fatalf("active write %d: %v", i, err)
		}
		time.Sleep(35 * time.Millisecond)
	}
	select {
	case err := <-readDone:
		t.Fatalf("one-way active traffic was treated as idle: %v", err)
	default:
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("idle read unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("shared idle timer did not expire after all traffic stopped")
	}
	<-peerReadDone
}

func TestManagerStartsLocalForwardAndBridgesAuthenticatedStream(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	connector := &pipeConnector{opened: make(chan net.Conn, 1)}
	log := &memoryAudit{}
	manager, auth, listener := newManagerForTest(t, testInitiator, claims, connector, log, nil, nil)
	info, err := manager.Start(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if info.ListenerAddress != "127.0.0.1:43123" || info.Direction != DirectionLocal {
		t.Fatalf("forward info = %#v", info)
	}
	client, core := net.Pipe()
	if !listener.inject(core) {
		t.Fatal("listener closed before accept")
	}
	var remote net.Conn
	select {
	case remote = <-connector.opened:
		forwarded := connector.lastAuth()
		if forwarded.Signature != auth.Signature || forwarded.Claims.ForwardingID != claims.ForwardingID {
			t.Fatal("destination connector did not receive the original signed authorization")
		}
	case <-time.After(time.Second):
		t.Fatal("connector was not called")
	}
	defer remote.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(remote, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "request" {
		t.Fatalf("forwarded bytes = %q", buf)
	}
	if _, err := remote.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 5)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "reply" {
		t.Fatalf("response = %q", response)
	}
	if err := manager.Stop(context.Background(), claims.ForwardingID); err != nil {
		t.Fatal(err)
	}
	if len(manager.List()) != 0 {
		t.Fatal("forward remains active after Stop")
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("child connection remained open after Stop")
	}
	_ = client.Close()
	if len(log.snapshot()) < 4 {
		t.Fatalf("expected lifecycle audit events, got %d", len(log.snapshot()))
	}
}

func TestManagerMultiplexesMultipleChildrenOverOneParentSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	connector := &pipeConnector{opened: make(chan net.Conn, 2)}
	manager, auth, listener := newManagerForTest(t, testInitiator, claims, connector, nil, nil, nil)
	if _, err := manager.Start(context.Background(), auth); err != nil {
		t.Fatal(err)
	}

	firstClient, firstCore := net.Pipe()
	if !listener.inject(firstCore) {
		t.Fatal("first child listener injection failed")
	}
	secondClient, secondCore := net.Pipe()
	if !listener.inject(secondCore) {
		t.Fatal("second child listener injection failed")
	}
	defer firstClient.Close()
	defer secondClient.Close()

	var firstRemote, secondRemote net.Conn
	select {
	case firstRemote = <-connector.opened:
	case <-time.After(time.Second):
		t.Fatal("first child stream was not opened")
	}
	select {
	case secondRemote = <-connector.opened:
	case <-time.After(time.Second):
		t.Fatal("second child stream was not opened")
	}
	defer firstRemote.Close()
	defer secondRemote.Close()

	if connector.callCount() != 1 {
		t.Fatalf("parent connector opened %d times, want one authenticated session", connector.callCount())
	}
	if got := connector.lastAuth(); got.Signature != auth.Signature || got.Claims.ForwardingID != claims.ForwardingID {
		t.Fatal("parent session did not receive the signed forwarding capability")
	}

	if _, err := firstClient.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	firstBytes := make([]byte, 3)
	if _, err := io.ReadFull(firstRemote, firstBytes); err != nil || string(firstBytes) != "one" {
		t.Fatalf("first child payload = %q, error = %v", firstBytes, err)
	}
	if _, err := secondClient.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	secondBytes := make([]byte, 3)
	if _, err := io.ReadFull(secondRemote, secondBytes); err != nil || string(secondBytes) != "two" {
		t.Fatalf("second child payload = %q, error = %v", secondBytes, err)
	}

	_ = firstClient.Close()
	deadline := time.After(time.Second)
	for len(manager.List()) == 0 || manager.List()[0].ActiveConnections != 1 {
		select {
		case <-deadline:
			t.Fatal("first child did not release its parent-session slot")
		case <-time.After(10 * time.Millisecond):
		}
	}
	thirdClient, thirdCore := net.Pipe()
	if !listener.inject(thirdCore) {
		t.Fatal("sequential child listener injection failed")
	}
	defer thirdClient.Close()
	var thirdRemote net.Conn
	select {
	case thirdRemote = <-connector.opened:
	case <-time.After(time.Second):
		t.Fatal("sequential child stream was not opened")
	}
	defer thirdRemote.Close()
	if connector.callCount() != 1 {
		t.Fatalf("sequential child opened %d parent sessions, want one", connector.callCount())
	}
	if _, err := thirdClient.Write([]byte("three")); err != nil {
		t.Fatal(err)
	}
	thirdBytes := make([]byte, 5)
	if _, err := io.ReadFull(thirdRemote, thirdBytes); err != nil || string(thirdBytes) != "three" {
		t.Fatalf("sequential child payload = %q, error = %v", thirdBytes, err)
	}

	if err := manager.Stop(context.Background(), claims.ForwardingID); err != nil {
		t.Fatal(err)
	}
}

func TestManagerRemoteForwardRunsOnRemoteListenerDevice(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionRemote)
	claims.Permission = PermissionRemote
	connector := &pipeConnector{}
	manager, auth, listener := newManagerForTest(t, testDestination, claims, connector, nil, nil, nil)
	if _, err := manager.Start(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	if len(manager.List()) != 1 {
		t.Fatal("remote forward did not start")
	}
	if err := manager.Stop(context.Background(), claims.ForwardingID); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listener error = %v", err)
	}
}

func TestManagerRequiresSeparateRouteAuthorizationForRouterPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testRoutedClaims(now, DirectionLocal)
	manager, auth, _ := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, nil, nil, nil)
	if _, err := manager.Start(context.Background(), auth); !errors.Is(err, ErrRouteAuthorizationRequired) {
		t.Fatalf("Start error = %v, want separate route-authorization requirement", err)
	}
	if len(manager.List()) != 0 {
		t.Fatal("routed forward started without routing authorization")
	}
}

func TestManagerPassesSeparateRouteAuthorizationToConnector(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testRoutedClaims(now, DirectionLocal)
	connector := &pipeConnector{opened: make(chan net.Conn, 1)}
	manager, auth, listener := newManagerForTest(t, testInitiator, claims, connector, nil, nil, nil)
	routeAuth, _ := testRouteAuthorization(t, claims)
	auth.RouteAuthorization = routeAuth
	if _, err := manager.Start(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	client, core := net.Pipe()
	if !listener.inject(core) {
		t.Fatal("listener closed before accept")
	}
	var remote net.Conn
	select {
	case remote = <-connector.opened:
	case <-time.After(time.Second):
		t.Fatal("connector was not called")
	}
	defer remote.Close()
	if connector.lastAuth().RouteAuthorization.Signature != routeAuth.Signature {
		t.Fatal("connector did not receive the independent route authorization")
	}
	if err := manager.Stop(context.Background(), claims.ForwardingID); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
}

func TestManagerRejectsMissingAuthorization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	manager, _, _ := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, nil, nil, nil)
	if _, err := manager.Start(context.Background(), Authorization{}); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("Start error = %v, want missing-authorization rejection", err)
	}
	if len(manager.List()) != 0 {
		t.Fatal("missing authorization created a listener")
	}
}

func TestManagerRejectsMissingLocalPermissionAuthorizer(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewManager(ManagerConfig{
		LocalDeviceID: testInitiator,
		Verifier:      AuthorizationVerifier{PublicKey: publicKey, Replay: NewMemoryReplay(8)},
		Connector:     &pipeConnector{},
		Audit:         &memoryAudit{},
		Limits:        managerTestLimits(),
	})
	if !errors.Is(err, ErrManagerConfig) {
		t.Fatalf("NewManager error = %v, want missing permission-authority rejection", err)
	}
}

func TestManagerEnforcesDirectionSpecificPermission(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionRemote)
	claims.Permission = PermissionRemote
	listenCalls := 0
	manager, auth, _ := newManagerForTestWithPermission(
		t,
		testDestination,
		claims,
		&pipeConnector{},
		nil,
		nil,
		grantPortForwardPermission{permission: PermissionLocal},
		func(string, string) (net.Listener, error) {
			listenCalls++
			return newQueueListener(), nil
		},
	)
	if _, err := manager.Start(context.Background(), auth); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Start error = %v, want dedicated-permission rejection", err)
	}
	if listenCalls != 0 || len(manager.List()) != 0 {
		t.Fatal("wrong direction permission created a listener")
	}
}

func TestManagerRejectsRemoteForwardOnInitiatorDevice(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionRemote)
	claims.Permission = PermissionRemote
	manager, auth, _ := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, nil, nil, nil)
	if _, err := manager.Start(context.Background(), auth); !errors.Is(err, ErrWrongListenerDevice) {
		t.Fatalf("Start error = %v", err)
	}
	if len(manager.List()) != 0 {
		t.Fatal("wrong endpoint created a listener")
	}
}

func TestManagerRequiresSeparateRouterAdminForPublicListener(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.Listener = ListenerPolicy{Address: "1.1.1.1", Port: 43123, Exposure: ExposurePublic}
	manager, auth, _ := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, nil, nil, func(string, string) (net.Listener, error) { return listenerForTest(), nil })
	if _, err := manager.Start(context.Background(), auth); !errors.Is(err, ErrListenerAdminRequired) {
		t.Fatalf("Start error = %v", err)
	}
	if len(manager.List()) != 0 {
		t.Fatal("unauthorized public listener was created")
	}

	admin := &allowListenerAdmin{}
	manager2, auth2, _ := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, nil, admin, func(string, string) (net.Listener, error) { return newQueueListenerAddress("1.1.1.1"), nil })
	if _, err := manager2.Start(context.Background(), auth2); err != nil {
		t.Fatal(err)
	}
	if admin.calls != 1 {
		t.Fatalf("router-admin checks = %d", admin.calls)
	}
	if err := manager2.Close(); err != nil {
		t.Fatal(err)
	}
}

func listenerForTest() net.Listener { return newQueueListener() }

func TestManagerAuditFailurePreventsListenerCreation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	log := &memoryAudit{failType: "port_forward.start", failOutcome: "attempt"}
	listenCalls := 0
	manager, auth, _ := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, log, nil, func(string, string) (net.Listener, error) { listenCalls++; return listenerForTest(), nil })
	if _, err := manager.Start(context.Background(), auth); err == nil {
		t.Fatal("Start succeeded despite failed audit persistence")
	}
	if listenCalls != 0 {
		t.Fatalf("listener opened %d times despite audit failure", listenCalls)
	}
}

func TestManagerAuditFailureAfterBindClosesListener(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	log := &memoryAudit{failType: "port_forward.started", failOutcome: "success"}
	listener := newQueueListener()
	manager, auth, _ := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, log, nil, func(string, string) (net.Listener, error) { return listener, nil })
	if _, err := manager.Start(context.Background(), auth); err == nil {
		t.Fatal("Start succeeded despite missing durable success audit")
	}
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("listener leaked after audit failure")
	}
	if len(manager.List()) != 0 {
		t.Fatal("failed start remained active")
	}
}

func TestManagerEnforcesPerForwardConnectionLimitAndStopsChildren(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.Limits.MaxConnections = 1
	block := make(chan struct{})
	connector := &pipeConnector{block: block, opened: make(chan net.Conn, 2)}
	manager, auth, listener := newManagerForTest(t, testInitiator, claims, connector, nil, nil, nil)
	if _, err := manager.Start(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	firstClient, firstCore := net.Pipe()
	if !listener.inject(firstCore) {
		t.Fatal("first accept failed")
	}
	select {
	case <-connector.opened:
	case <-time.After(time.Second):
		t.Fatal("first connector not invoked")
	}
	secondClient, secondCore := net.Pipe()
	if !listener.inject(secondCore) {
		t.Fatal("second accept failed")
	}
	_ = secondClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := secondClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-limit connection remained open")
	}
	if connector.callCount() != 1 {
		t.Fatalf("connector calls = %d", connector.callCount())
	}
	if err := manager.Stop(context.Background(), claims.ForwardingID); err != nil {
		t.Fatal(err)
	}
	_ = firstClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := firstClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("child remained open after Stop")
	}
	_ = firstClient.Close()
	_ = secondClient.Close()
}

type blockingListenerAdmin struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (a *blockingListenerAdmin) AuthorizePortForwardListener(ctx context.Context, _ Claims) error {
	a.once.Do(func() { close(a.started) })
	select {
	case <-a.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestManagerCloseCancelsPendingStart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	admin := &blockingListenerAdmin{started: make(chan struct{}), release: make(chan struct{})}
	listenCalls := 0
	manager, auth, _ := newManagerForTest(
		t,
		testInitiator,
		claims,
		&pipeConnector{},
		nil,
		admin,
		func(string, string) (net.Listener, error) {
			listenCalls++
			return newQueueListener(), nil
		},
	)

	startResult := make(chan error, 1)
	go func() {
		_, err := manager.Start(context.Background(), auth)
		startResult <- err
	}()
	select {
	case <-admin.started:
	case <-time.After(time.Second):
		t.Fatal("start did not reach listener authorization")
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- manager.Close() }()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("manager close did not cancel the pending start")
	}
	select {
	case err := <-startResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pending Start error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending start did not exit after manager close")
	}
	if listenCalls != 0 || len(manager.List()) != 0 {
		t.Fatal("manager close allowed a pending listener to start")
	}
}

func TestManagerDeviceRevocationCancelsPendingStart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.Listener = ListenerPolicy{Address: "1.1.1.1", Port: 43123, Exposure: ExposurePublic}
	admin := &blockingListenerAdmin{started: make(chan struct{}), release: make(chan struct{})}
	listener := newQueueListenerAddress("1.1.1.1")
	manager, auth, _ := newManagerForTest(
		t,
		testInitiator,
		claims,
		&pipeConnector{},
		nil,
		admin,
		func(string, string) (net.Listener, error) { return listener, nil },
	)

	startResult := make(chan error, 1)
	go func() {
		_, err := manager.Start(context.Background(), auth)
		startResult <- err
	}()
	select {
	case <-admin.started:
	case <-time.After(time.Second):
		t.Fatal("start did not reach pending listener authorization")
	}

	count, err := manager.RevokeDevice(context.Background(), testDestination)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("revoked count = %d, want pending start included", count)
	}
	close(admin.release)

	select {
	case err := <-startResult:
		if !errors.Is(err, ErrForwardRevoked) {
			t.Fatalf("pending Start error = %v, want revoked", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending start did not stop after device revocation")
	}
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("listener leaked after pending-start revocation")
	}
	if len(manager.List()) != 0 {
		t.Fatal("revoked pending forward became active")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerDeviceRevocationTerminatesForward(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	connector := &pipeConnector{opened: make(chan net.Conn, 1)}
	manager, auth, listener := newManagerForTest(t, testInitiator, claims, connector, nil, nil, nil)
	if _, err := manager.Start(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	client, core := net.Pipe()
	listener.inject(core)
	var remote net.Conn
	select {
	case remote = <-connector.opened:
	case <-time.After(time.Second):
		t.Fatal("connector not called")
	}
	defer remote.Close()
	count, err := manager.RevokeDevice(context.Background(), testDestination)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(manager.List()) != 0 {
		t.Fatalf("revoked count=%d active=%d", count, len(manager.List()))
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked child connection remained open")
	}
	_ = client.Close()
}

func TestManagerExpiryTerminatesListener(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.ExpiresAtUnixMS = now.Add(150 * time.Millisecond).UnixMilli()
	claims.Route.ExpiresAt = time.UnixMilli(claims.ExpiresAtUnixMS).UTC()
	claims.Limits.MaxDurationSeconds = 1
	listener := newQueueListener()
	manager, auth, _ := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, nil, nil, func(string, string) (net.Listener, error) { return listener, nil })
	if _, err := manager.Start(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	select {
	case <-listener.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("listener remained open after capability expiry")
	}
	deadline := time.After(time.Second)
	for len(manager.List()) != 0 {
		select {
		case <-deadline:
			t.Fatal("expired forward remains registered")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestManagerRejectsDuplicateForwardingIDWithoutConsumingSecondCapability(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	manager, auth, _ := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, nil, nil, nil)
	if _, err := manager.Start(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Start(context.Background(), auth); !errors.Is(err, ErrForwardExists) {
		t.Fatalf("duplicate Start error = %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerLimitsArePositiveAndBounded(t *testing.T) {
	limits := managerTestLimits()
	limits.MaxConnections = 0
	_, err := NewManager(ManagerConfig{LocalDeviceID: testInitiator, Verifier: AuthorizationVerifier{}, PermissionAuthorizer: allowPortForwardPermission{}, Connector: &pipeConnector{}, Audit: &memoryAudit{}, Limits: limits})
	if !errors.Is(err, ErrManagerConfig) {
		t.Fatalf("NewManager error = %v", err)
	}
}

func TestManagerConnectionAuditFailureTerminatesForward(t *testing.T) {
	claims := testClaims(time.Now().UTC().Truncate(time.Millisecond), DirectionLocal)
	log := &memoryAudit{failType: "port_forward.connection_opened", failOutcome: "attempt"}
	manager, auth, listener := newManagerForTest(t, testInitiator, claims, &pipeConnector{}, log, nil, nil)
	if _, err := manager.Start(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	client, core := net.Pipe()
	if !listener.inject(core) {
		t.Fatal("listener closed before accept")
	}
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("listener remained active after audit persistence failure")
	}
	deadline := time.After(time.Second)
	for len(manager.List()) != 0 {
		select {
		case <-deadline:
			t.Fatal("forward remained registered after audit persistence failure")
		case <-time.After(5 * time.Millisecond):
		}
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("child connection survived audit persistence failure")
	}
	_ = client.Close()
}

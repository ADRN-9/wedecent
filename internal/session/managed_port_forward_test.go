package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/portforward"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

type forwardingTestAudit struct{}

func (forwardingTestAudit) Append(audit.Event) error { return nil }

type forwardingTestResolver struct{}

func (forwardingTestResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "ip" || host != "forward.test" {
		return nil, errors.New("unexpected test resolver query")
	}
	return []netip.Addr{netip.MustParseAddr("10.20.30.40")}, nil
}

type forwardingTestDialer struct {
	address string
}

func (d forwardingTestDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

type forwardingTestDirectAuthorizer struct{}

func (forwardingTestDirectAuthorizer) Authorize(context.Context, string, string, string) error {
	return nil
}

func TestManagedPortForwardUsesAuthenticatedTLSAndPreservesTCPHalfClose(t *testing.T) {
	clientID, serverID, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	serverFingerprint, err := identity.FingerprintPublicKey(clientID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverTrust, err := trust.Open(filepath.Join(t.TempDir(), "server-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := serverTrust.Put(trust.Peer{ID: clientID.ID, Fingerprint: serverFingerprint}); err != nil {
		t.Fatal(err)
	}
	clientFingerprint, err := identity.FingerprintPublicKey(serverID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	clientTrust, err := trust.Open(filepath.Join(t.TempDir(), "client-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := clientTrust.Put(trust.Peer{ID: serverID.ID, Fingerprint: clientFingerprint, Endpoint: peer.Endpoint}); err != nil {
		t.Fatal(err)
	}

	destinationListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destinationListener.Close()
	destinationDone := make(chan error, 1)
	go func() {
		conn, err := destinationListener.Accept()
		if err != nil {
			destinationDone <- err
			return
		}
		defer conn.Close()
		request, err := io.ReadAll(conn)
		if err != nil {
			destinationDone <- err
			return
		}
		if string(request) != "request-half-close" {
			destinationDone <- errors.New("destination received unexpected request")
			return
		}
		if _, err := conn.Write([]byte("complete-response")); err != nil {
			destinationDone <- err
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			if err := tcp.CloseWrite(); err != nil {
				destinationDone <- err
				return
			}
		}
		destinationDone <- nil
	}()

	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	sourceID, destinationID := mesh.DeviceID(clientID.ID), mesh.DeviceID(serverID.ID)
	claims := portforward.Claims{
		Version: portforward.AuthorizationVersion,
		Issuer: portforward.AuthorizationIssuerID,
		Audience: portforward.AuthorizationAudience,
		Permission: portforward.PermissionLocal,
		ForwardingID: "00000000-0000-4000-8000-000000000101",
		Direction: portforward.DirectionLocal,
		InitiatingDevice: sourceID,
		DestinationDevice: destinationID,
		Route: mesh.Route{
			ID: "00000000-0000-4000-8000-000000000102",
			Source: sourceID,
			Destination: destinationID,
			Hops: []mesh.RouteHop{{From: sourceID, To: destinationID, Transport: mesh.TransportInternet, Cost: 1}},
		},
		DestinationAddress: "forward.test",
		DestinationPort: 443,
		Listener: portforward.DefaultListenerPolicy(43123),
		Protocol: portforward.ProtocolTCP,
		Limits: portforward.ResourceLimits{MaxConnections: 2, MaxDurationSeconds: 30, IdleTimeoutSeconds: 5},
	}
	auth, err := (portforward.AuthorizationIssuer{
		Signer: signingKey, Lifetime: 30 * time.Second, Now: func() time.Time { return now },
	}).Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}

	forwardRuntime := &PortForwardRuntime{
		Verifier: &portforward.AuthorizationVerifier{PublicKey: publicKey, Replay: portforward.NewMemoryReplay(8), Now: func() time.Time { return now }},
		TrustChecker: serverTrust,
		PermissionAuthorizer: portforward.CapabilityPermissionAuthorizer{},
		Resolver: forwardingTestResolver{},
		Dialer: forwardingTestDialer{address: destinationListener.Addr().String()},
		Policy: portforward.DestinationPolicy{
			AllowedPorts: []portforward.PortRange{{First: 443, Last: 443}},
			AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")},
		},
		Audit: forwardingTestAudit{},
		MaxConnections: 2,
		DialTimeout: 5 * time.Second,
	}
	if !forwardRuntime.Ready() {
		t.Fatal("destination forwarding runtime is not ready")
	}
	server := &Server{
		Identity: serverID,
		Trust: serverTrust,
		DirectAuthorizer: forwardingTestDirectAuthorizer{},
		PortForwarding: forwardRuntime,
		Policy: SessionPolicy{IdleTimeout: time.Minute, MaxDuration: time.Minute},
	}

	clientSide, serverSide := net.Pipe()
	dialer := &managedTestDialer{conn: clientSide}
	serverDone := make(chan struct{})
	go func() {
		server.ServeConn(serverSide)
		close(serverDone)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := &Client{
		Identity: clientID, Trust: clientTrust, Dialer: dialer,
		ConnectionGrant: "test.connection.grant",
		ForceInBandAuthorization: true,
	}
	managed, err := client.OpenManagedPortForwardSession(ctx, peer, auth)
	if err != nil {
		t.Fatal(err)
	}
	child, err := managed.OpenChild(ctx)
	if err != nil {
		_ = managed.Close()
		t.Fatal(err)
	}
	if _, err := child.Write([]byte("request-half-close")); err != nil {
		t.Fatal(err)
	}
	if err := child.(*ManagedPortForwardConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(child)
	if err != nil || string(response) != "complete-response" {
		t.Fatalf("forwarded response = %q, error = %v", response, err)
	}
	if err := <-destinationDone; err != nil {
		t.Fatal(err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated forwarding parent did not terminate")
	}
}


type blockingForwardTestConn struct {
	net.Conn
	remote    net.Conn
	started   chan struct{}
	closed    chan struct{}
	writeOnce sync.Once
	closeOnce sync.Once
}

func (c *blockingForwardTestConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func (c *blockingForwardTestConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		closeErr = c.Conn.Close()
		close(c.closed)
	})
	return closeErr
}

type blockingForwardTestDialer struct {
	opened chan *blockingForwardTestConn
}

func (d *blockingForwardTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp" || address != "10.20.30.40:443" {
		return nil, errors.New("unexpected blocking test dial")
	}
	local, remote := net.Pipe()
	conn := &blockingForwardTestConn{
		Conn: local, remote: remote,
		started: make(chan struct{}), closed: make(chan struct{}),
	}
	select {
	case d.opened <- conn:
		return conn, nil
	case <-ctx.Done():
		_ = conn.Close()
		_ = remote.Close()
		return nil, ctx.Err()
	}
}

func TestTypedForwardBlockedChildDoesNotStallSiblingAndParentDisconnectClosesIt(t *testing.T) {
	clientID, serverID, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	serverFingerprint, err := identity.FingerprintPublicKey(clientID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverTrust, err := trust.Open(filepath.Join(t.TempDir(), "server-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := serverTrust.Put(trust.Peer{ID: clientID.ID, Fingerprint: serverFingerprint}); err != nil {
		t.Fatal(err)
	}
	clientFingerprint, err := identity.FingerprintPublicKey(serverID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	clientTrust, err := trust.Open(filepath.Join(t.TempDir(), "client-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := clientTrust.Put(trust.Peer{ID: serverID.ID, Fingerprint: clientFingerprint, Endpoint: peer.Endpoint}); err != nil {
		t.Fatal(err)
	}

	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	sourceID, destinationID := mesh.DeviceID(clientID.ID), mesh.DeviceID(serverID.ID)
	claims := portforward.Claims{
		Version: portforward.AuthorizationVersion,
		Issuer: portforward.AuthorizationIssuerID,
		Audience: portforward.AuthorizationAudience,
		Permission: portforward.PermissionLocal,
		ForwardingID: "00000000-0000-4000-8000-000000000201",
		Direction: portforward.DirectionLocal,
		InitiatingDevice: sourceID,
		DestinationDevice: destinationID,
		Route: mesh.Route{
			ID: "00000000-0000-4000-8000-000000000202",
			Source: sourceID,
			Destination: destinationID,
			Hops: []mesh.RouteHop{{From: sourceID, To: destinationID, Transport: mesh.TransportInternet, Cost: 1}},
		},
		DestinationAddress: "forward.test",
		DestinationPort: 443,
		Listener: portforward.DefaultListenerPolicy(43124),
		Protocol: portforward.ProtocolTCP,
		Limits: portforward.ResourceLimits{MaxConnections: 2, MaxDurationSeconds: 30, IdleTimeoutSeconds: 5},
	}
	auth, err := (portforward.AuthorizationIssuer{
		Signer: signingKey, Lifetime: 30 * time.Second, Now: func() time.Time { return now },
	}).Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}

	destinationDialer := &blockingForwardTestDialer{opened: make(chan *blockingForwardTestConn, 2)}
	forwardRuntime := &PortForwardRuntime{
		Verifier: &portforward.AuthorizationVerifier{PublicKey: publicKey, Replay: portforward.NewMemoryReplay(8), Now: func() time.Time { return now }},
		TrustChecker: serverTrust,
		PermissionAuthorizer: portforward.CapabilityPermissionAuthorizer{},
		Resolver: forwardingTestResolver{},
		Dialer: destinationDialer,
		Policy: portforward.DestinationPolicy{
			AllowedPorts: []portforward.PortRange{{First: 443, Last: 443}},
			AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")},
		},
		Audit: forwardingTestAudit{},
		MaxConnections: 2,
		DialTimeout: 5 * time.Second,
	}
	if !forwardRuntime.Ready() {
		t.Fatal("destination forwarding runtime is not ready")
	}
	server := &Server{
		Identity: serverID, Trust: serverTrust,
		DirectAuthorizer: forwardingTestDirectAuthorizer{},
		PortForwarding: forwardRuntime,
		Policy: SessionPolicy{IdleTimeout: time.Minute, MaxDuration: time.Minute},
	}

	clientSide, serverSide := net.Pipe()
	dialer := &managedTestDialer{conn: clientSide}
	serverDone := make(chan struct{})
	go func() {
		server.ServeConn(serverSide)
		close(serverDone)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := &Client{
		Identity: clientID, Trust: clientTrust, Dialer: dialer,
		ConnectionGrant: "test.connection.grant",
		ForceInBandAuthorization: true,
	}
	managed, err := client.OpenManagedPortForwardSession(ctx, peer, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = managed.finish() })

	first, err := managed.OpenChild(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := managed.OpenChild(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var blocked, responsive *blockingForwardTestConn
	for i := 0; i < 2; i++ {
		select {
		case opened := <-destinationDialer.opened:
			if i == 0 {
				blocked = opened
			} else {
				responsive = opened
			}
		case <-ctx.Done():
			t.Fatal("destination child connections were not opened")
		}
	}
	defer blocked.remote.Close()
	defer responsive.remote.Close()

	if _, err := first.Write([]byte("blocked")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked.started:
	case <-ctx.Done():
		t.Fatal("first destination write did not block")
	}

	secondRead := make(chan error, 1)
	go func() {
		got := make([]byte, 2)
		_, err := io.ReadFull(responsive.remote, got)
		if err == nil && string(got) != "ok" {
			err = errors.New("sibling received unexpected payload")
		}
		secondRead <- err
	}()
	if _, err := second.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-secondRead:
		if err != nil {
			t.Fatalf("sibling stream stalled behind blocked child: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("sibling stream did not make progress while another child write was blocked")
	}

	// Closing the authenticated parent must cancel the destination session
	// and close the child whose destination Write is blocked.
	_ = managed.finish()
	select {
	case <-blocked.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked destination child remained open after parent disconnect")
	}
	select {
	case <-responsive.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("sibling destination child remained open after parent disconnect")
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("typed parent session did not terminate after transport disconnect")
	}
}

func managedPortForwardTLSForTest(t *testing.T) (*tls.Conn, *tls.Conn) {
	t.Helper()
	clientID, serverID, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	clientSide, serverSide := net.Pipe()
	clientConn := tls.Client(clientSide, identity.ClientTLS(clientID, peer.Fingerprint))
	serverConn := tls.Server(serverSide, identity.ServerTLS(serverID))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	handshakeErr := make(chan error, 2)
	go func() { handshakeErr <- clientConn.HandshakeContext(ctx) }()
	go func() { handshakeErr <- serverConn.HandshakeContext(ctx) }()
	for i := 0; i < 2; i++ {
		if err := <-handshakeErr; err != nil {
			_ = clientConn.NetConn().Close()
			_ = serverConn.NetConn().Close()
			t.Fatalf("TLS test handshake failed: %v", err)
		}
	}
	t.Cleanup(func() {
		_ = clientConn.NetConn().Close()
		_ = serverConn.NetConn().Close()
	})
	return clientConn, serverConn
}

func TestManagedPortForwardShutdownInterruptsBlockedTransportWrite(t *testing.T) {
	clientConn, _ := managedPortForwardTLSForTest(t)
	s := &ManagedPortForwardSession{
		conn: clientConn, states: make(map[uint32]*managedPortForwardState),
		done: make(chan struct{}), writeLock: make(chan struct{}, 1),
	}
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- s.writeFrameContext(context.Background(), protocol.Frame{Type: protocol.TypePing}, time.Time{})
	}()
	deadline := time.Now().Add(time.Second)
	for len(s.writeLock) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.writeLock) == 0 {
		t.Fatal("test writer did not acquire the transport write lock")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("session close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session shutdown waited for the blocked TLS write")
	}
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("forced parent transport close did not interrupt the blocked TLS write")
	}
}

func TestManagedPortForwardShutdownDoesNotWaitForOccupiedWriteLock(t *testing.T) {
	clientConn, _ := managedPortForwardTLSForTest(t)
	s := &ManagedPortForwardSession{
		conn: clientConn, states: make(map[uint32]*managedPortForwardState),
		done: make(chan struct{}), writeLock: make(chan struct{}, 1),
	}
	s.writeLock <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypePing}, time.Time{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write waiting for lock = %v, want context.Canceled", err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("session close failed with occupied write lock: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session shutdown waited for the occupied transport write lock")
	}
}


type parentCloseBlockingConn struct {
	net.Conn
	remote  net.Conn
	started chan struct{}
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *parentCloseBlockingConn) Close() error {
	c.once.Do(func() {
		close(c.started)
		<-c.release
		_ = c.Conn.Close()
		close(c.closed)
	})
	return nil
}

type parentCloseBlockingDialer struct {
	opened chan *parentCloseBlockingConn
}

func (d *parentCloseBlockingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp" || address != "10.20.30.40:443" {
		return nil, errors.New("unexpected parent-close test dial")
	}
	local, remote := net.Pipe()
	conn := &parentCloseBlockingConn{
		Conn: local, remote: remote,
		started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}),
	}
	select {
	case d.opened <- conn:
		return conn, nil
	case <-ctx.Done():
		_ = conn.Close()
		_ = remote.Close()
		return nil, ctx.Err()
	}
}

func TestTypedForwardParentCloseDoesNotWaitForBlockedChildClose(t *testing.T) {
	clientID, serverID, _ := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	fingerprint, err := identity.FingerprintPublicKey(clientID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverTrust, err := trust.Open(filepath.Join(t.TempDir(), "server-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := serverTrust.Put(trust.Peer{ID: clientID.ID, Fingerprint: fingerprint}); err != nil {
		t.Fatal(err)
	}
	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	sourceID, destinationID := mesh.DeviceID(clientID.ID), mesh.DeviceID(serverID.ID)
	claims := portforward.Claims{
		Version: portforward.AuthorizationVersion, Issuer: portforward.AuthorizationIssuerID,
		Audience: portforward.AuthorizationAudience, Permission: portforward.PermissionLocal,
		ForwardingID: "00000000-0000-4000-8000-000000000301", Direction: portforward.DirectionLocal,
		InitiatingDevice: sourceID, DestinationDevice: destinationID,
		Route: mesh.Route{
			ID: "00000000-0000-4000-8000-000000000302", Source: sourceID, Destination: destinationID,
			Hops: []mesh.RouteHop{{From: sourceID, To: destinationID, Transport: mesh.TransportInternet, Cost: 1}},
		},
		DestinationAddress: "forward.test", DestinationPort: 443,
		Listener: portforward.DefaultListenerPolicy(43125), Protocol: portforward.ProtocolTCP,
		Limits: portforward.ResourceLimits{MaxConnections: 1, MaxDurationSeconds: 30, IdleTimeoutSeconds: 5},
	}
	auth, err := (portforward.AuthorizationIssuer{
		Signer: signingKey, Lifetime: 30 * time.Second, Now: func() time.Time { return now },
	}).Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &parentCloseBlockingDialer{opened: make(chan *parentCloseBlockingConn, 1)}
	runtime := &PortForwardRuntime{
		Verifier: &portforward.AuthorizationVerifier{PublicKey: publicKey, Replay: portforward.NewMemoryReplay(8), Now: func() time.Time { return now }},
		TrustChecker: serverTrust, PermissionAuthorizer: portforward.CapabilityPermissionAuthorizer{},
		Resolver: forwardingTestResolver{}, Dialer: dialer,
		Policy: portforward.DestinationPolicy{
			AllowedPorts: []portforward.PortRange{{First: 443, Last: 443}},
			AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")},
		},
		Audit: forwardingTestAudit{}, MaxConnections: 1, DialTimeout: 5 * time.Second,
	}
	server := newTypedPortForwardServer(context.Background(), serverID.ID, clientID.ID, "", runtime, newTypedParentStreamRegistry(), func(protocol.Frame) error { return nil })
	parentMetadata, err := protocol.JSON(portForwardParentOpen{Authorization: auth})
	if err != nil {
		t.Fatal(err)
	}
	parentPayload, err := protocol.JSON(protocol.StreamOpen{
		Kind: protocol.StreamKindPortForwardParent, Metadata: parentMetadata, InitialWindow: managedPortForwardReceiveWindow,
	})
	if err != nil {
		t.Fatal(err)
	}
	parentID, childID := protocol.MinTypedStreamID, protocol.MinTypedStreamID+1
	if err := server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: parentID, Payload: parentPayload}); err != nil {
		t.Fatal(err)
	}
	childMetadata, err := protocol.JSON(portForwardChildOpen{ParentStreamID: parentID})
	if err != nil {
		t.Fatal(err)
	}
	childPayload, err := protocol.JSON(protocol.StreamOpen{
		Kind: protocol.StreamKindPortForwardChild, Metadata: childMetadata, InitialWindow: managedPortForwardReceiveWindow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: childID, Payload: childPayload}); err != nil {
		t.Fatal(err)
	}
	blocked := <-dialer.opened
	released := false
	defer func() {
		if !released {
			close(blocked.release)
		}
		_ = blocked.remote.Close()
	}()

	server.mu.Lock()
	child := server.children[childID]
	server.mu.Unlock()
	if child == nil {
		t.Fatal("forwarding child was not registered")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- server.closeParent(parentID, "test_parent_close", false) }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("destination child close did not reach the blocking connection")
	}
	select {
	case err := <-closeDone:
		if err == nil {
			t.Fatal("parent close hid the destination child cleanup timeout")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("parent close waited on a second Close call after destination cleanup timed out")
	}
	select {
	case <-child.done:
	case <-time.After(time.Second):
		t.Fatal("parent close did not signal child completion")
	}
	close(blocked.release)
	released = true
	select {
	case <-blocked.closed:
	case <-time.After(time.Second):
		t.Fatal("blocked destination connection did not close after release")
	}
}


type parentCloseBlockingAudit struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *parentCloseBlockingAudit) Append(event audit.Event) error {
	if event.Type == "port_forward.destination_child" && event.Outcome == "success" {
		w.once.Do(func() {
			close(w.started)
			<-w.release
		})
	}
	return nil
}

func TestTypedForwardOpenChildDoesNotDoubleCloseDuringParentShutdown(t *testing.T) {
	clientID, serverID, _ := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	fingerprint, err := identity.FingerprintPublicKey(clientID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverTrust, err := trust.Open(filepath.Join(t.TempDir(), "server-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := serverTrust.Put(trust.Peer{ID: clientID.ID, Fingerprint: fingerprint}); err != nil {
		t.Fatal(err)
	}
	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	sourceID, destinationID := mesh.DeviceID(clientID.ID), mesh.DeviceID(serverID.ID)
	claims := portforward.Claims{
		Version: portforward.AuthorizationVersion, Issuer: portforward.AuthorizationIssuerID,
		Audience: portforward.AuthorizationAudience, Permission: portforward.PermissionLocal,
		ForwardingID: "00000000-0000-4000-8000-000000000303", Direction: portforward.DirectionLocal,
		InitiatingDevice: sourceID, DestinationDevice: destinationID,
		Route: mesh.Route{
			ID: "00000000-0000-4000-8000-000000000304", Source: sourceID, Destination: destinationID,
			Hops: []mesh.RouteHop{{From: sourceID, To: destinationID, Transport: mesh.TransportInternet, Cost: 1}},
		},
		DestinationAddress: "forward.test", DestinationPort: 443,
		Listener: portforward.DefaultListenerPolicy(43126), Protocol: portforward.ProtocolTCP,
		Limits: portforward.ResourceLimits{MaxConnections: 1, MaxDurationSeconds: 30, IdleTimeoutSeconds: 5},
	}
	auth, err := (portforward.AuthorizationIssuer{
		Signer: signingKey, Lifetime: 30 * time.Second, Now: func() time.Time { return now },
	}).Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &parentCloseBlockingDialer{opened: make(chan *parentCloseBlockingConn, 1)}
	auditLog := &parentCloseBlockingAudit{started: make(chan struct{}), release: make(chan struct{})}
	auditReleased := false
	defer func() {
		if !auditReleased {
			close(auditLog.release)
		}
	}()
	runtime := &PortForwardRuntime{
		Verifier: &portforward.AuthorizationVerifier{PublicKey: publicKey, Replay: portforward.NewMemoryReplay(8), Now: func() time.Time { return now }},
		TrustChecker: serverTrust, PermissionAuthorizer: portforward.CapabilityPermissionAuthorizer{},
		Resolver: forwardingTestResolver{}, Dialer: dialer,
		Policy: portforward.DestinationPolicy{
			AllowedPorts: []portforward.PortRange{{First: 443, Last: 443}},
			AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")},
		},
		Audit: auditLog, MaxConnections: 1, DialTimeout: 5 * time.Second,
	}
	server := newTypedPortForwardServer(context.Background(), serverID.ID, clientID.ID, "", runtime, newTypedParentStreamRegistry(), func(protocol.Frame) error { return nil })
	parentMetadata, err := protocol.JSON(portForwardParentOpen{Authorization: auth})
	if err != nil {
		t.Fatal(err)
	}
	parentPayload, err := protocol.JSON(protocol.StreamOpen{
		Kind: protocol.StreamKindPortForwardParent, Metadata: parentMetadata, InitialWindow: managedPortForwardReceiveWindow,
	})
	if err != nil {
		t.Fatal(err)
	}
	parentID, childID := protocol.MinTypedStreamID, protocol.MinTypedStreamID+1
	if err := server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: parentID, Payload: parentPayload}); err != nil {
		t.Fatal(err)
	}
	childMetadata, err := protocol.JSON(portForwardChildOpen{ParentStreamID: parentID})
	if err != nil {
		t.Fatal(err)
	}
	childPayload, err := protocol.JSON(protocol.StreamOpen{
		Kind: protocol.StreamKindPortForwardChild, Metadata: childMetadata, InitialWindow: managedPortForwardReceiveWindow,
	})
	if err != nil {
		t.Fatal(err)
	}
	openDone := make(chan error, 1)
	go func() {
		openDone <- server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: childID, Payload: childPayload})
	}()
	select {
	case <-auditLog.started:
	case <-time.After(time.Second):
		t.Fatal("child open did not reach the blocking success audit append")
	}
	blocked := <-dialer.opened
	released := false
	defer func() {
		if !released {
			close(blocked.release)
		}
		_ = blocked.remote.Close()
	}()

	closeDone := make(chan error, 1)
	go func() { closeDone <- server.closeParent(parentID, "test_parent_close", false) }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("parent shutdown did not begin destination child cleanup")
	}
	select {
	case err := <-closeDone:
		if err == nil {
			t.Fatal("parent close hid the blocked child cleanup timeout")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("parent close did not finish within the destination cleanup deadline")
	}

	close(auditLog.release)
	auditReleased = true
	select {
	case err := <-openDone:
		if err != nil {
			t.Fatalf("late child open returned an unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late child open blocked on a duplicate destination child Close")
	}
	close(blocked.release)
	released = true
	select {
	case <-blocked.closed:
	case <-time.After(time.Second):
		t.Fatal("blocked destination connection did not close after release")
	}
}

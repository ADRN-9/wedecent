package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/portforward"
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
		Issuer: portforward.AuthorizationIssuer,
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

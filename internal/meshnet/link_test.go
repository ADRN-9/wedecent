package meshnet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/trust"
)

func testIdentity(t *testing.T, name string) *identity.Identity {
	t.Helper()

	id, err := identity.Ensure(filepath.Join(t.TempDir(), name), name)
	if err != nil {
		t.Fatalf("identity.Ensure() error: %v", err)
	}
	return id
}

func fingerprintForIdentity(t *testing.T, id *identity.Identity) string {
	t.Helper()

	fp, err := identity.FingerprintPublicKey(id.PublicKey)
	if err != nil {
		t.Fatalf("FingerprintPublicKey() error: %v", err)
	}
	return fp
}

func testTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}

	type acceptResult struct {
		conn net.Conn
		err  error
	}

	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	client, err := net.DialTimeout(
		"tcp",
		listener.Addr().String(),
		2*time.Second,
	)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("net.DialTimeout() error: %v", err)
	}

	result := <-accepted
	_ = listener.Close()

	if result.err != nil {
		_ = client.Close()
		t.Fatalf("listener.Accept() error: %v", result.err)
	}

	return client, result.conn
}

func testNeighborStore(
	t *testing.T,
	peers ...*identity.Identity,
) *trust.Store {
	t.Helper()

	store, err := trust.Open(filepath.Join(t.TempDir(), "router-peers.json"))
	if err != nil {
		t.Fatalf("trust.Open() error: %v", err)
	}

	for _, id := range peers {
		if err := store.Put(trust.Peer{
			ID:          id.ID,
			Name:        id.Name,
			Fingerprint: fingerprintForIdentity(t, id),
		}); err != nil {
			t.Fatalf("Store.Put() error: %v", err)
		}
	}

	return store
}

func TestTLSLinkAuthenticatesTrustedNeighbors(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	routerTrust := testNeighborStore(t, clientID)

	clientRaw, routerRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverCh := make(chan struct {
		link *TLSLink
		err  error
	}, 1)

	go func() {
		link, err := AcceptRouteControlLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportLAN,
		)
		serverCh <- struct {
			link *TLSLink
			err  error
		}{link: link, err: err}
	}()

	clientLink, err := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Transport:   mesh.TransportLAN,
		},
	)
	if err != nil {
		t.Fatalf("DialRouteControlLink() error: %v", err)
	}
	defer clientLink.Close()

	serverResult := <-serverCh
	if serverResult.err != nil {
		t.Fatalf("AcceptRouteControlLink() error: %v", serverResult.err)
	}
	defer serverResult.link.Close()

	if clientLink.Local() != mesh.DeviceID(clientID.ID) ||
		clientLink.Remote() != mesh.DeviceID(routerID.ID) ||
		clientLink.Transport() != mesh.TransportLAN {
		t.Fatalf(
			"client link metadata = local:%q remote:%q transport:%q",
			clientLink.Local(),
			clientLink.Remote(),
			clientLink.Transport(),
		)
	}

	if serverResult.link.Local() != mesh.DeviceID(routerID.ID) ||
		serverResult.link.Remote() != mesh.DeviceID(clientID.ID) ||
		serverResult.link.Transport() != mesh.TransportLAN {
		t.Fatalf(
			"server link metadata = local:%q remote:%q transport:%q",
			serverResult.link.Local(),
			serverResult.link.Remote(),
			serverResult.link.Transport(),
		)
	}

	want := []byte("opaque-inner-tls")
	writeErr := make(chan error, 1)
	go func() {
		_, err := clientLink.Write(want)
		writeErr <- err
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(serverResult.link, got); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("Write() error: %v", err)
	}
}

func TestDialTrustedLinkRejectsFingerprintMismatch(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	otherID := testIdentity(t, "other")
	routerTrust := testNeighborStore(t, clientID)

	clientRaw, routerRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		link, err := AcceptRouteControlLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportInternet,
		)
		if link != nil {
			_ = link.Close()
		}
		serverDone <- err
	}()

	link, err := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, otherID),
			Transport:   mesh.TransportInternet,
		},
	)
	if link != nil {
		_ = link.Close()
	}
	if !errors.Is(err, ErrNeighborIdentityMismatch) {
		t.Fatalf(
			"DialRouteControlLink() error = %v, want ErrNeighborIdentityMismatch",
			err,
		)
	}

	<-serverDone
}

func TestDialTrustedLinkRejectsDeviceIDMismatch(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	otherID := testIdentity(t, "other")
	routerTrust := testNeighborStore(t, clientID)

	clientRaw, routerRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		link, err := AcceptRouteControlLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportInternet,
		)
		if link != nil {
			_ = link.Close()
		}
		serverDone <- err
	}()

	link, err := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(otherID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Transport:   mesh.TransportInternet,
		},
	)
	if link != nil {
		_ = link.Close()
	}
	if !errors.Is(err, ErrNeighborIdentityMismatch) {
		t.Fatalf(
			"DialRouteControlLink() error = %v, want ErrNeighborIdentityMismatch",
			err,
		)
	}

	<-serverDone
}

func TestAcceptTrustedLinkRejectsUnknownNeighbor(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	routerTrust := testNeighborStore(t)

	clientRaw, routerRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		link, err := AcceptRouteControlLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportLAN,
		)
		if link != nil {
			_ = link.Close()
		}
		serverDone <- err
	}()

	link, _ := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Transport:   mesh.TransportLAN,
		},
	)
	if link != nil {
		_ = link.Close()
	}

	err := <-serverDone
	if !errors.Is(err, ErrNeighborUntrusted) {
		t.Fatalf(
			"AcceptRouteControlLink() error = %v, want ErrNeighborUntrusted",
			err,
		)
	}
}

func TestAcceptTrustedLinkRejectsPinnedFingerprintMismatch(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	otherID := testIdentity(t, "other")

	store, err := trust.Open(filepath.Join(t.TempDir(), "router-peers.json"))
	if err != nil {
		t.Fatalf("trust.Open() error: %v", err)
	}
	if err := store.Put(trust.Peer{
		ID:          clientID.ID,
		Fingerprint: fingerprintForIdentity(t, otherID),
	}); err != nil {
		t.Fatalf("Store.Put() error: %v", err)
	}

	clientRaw, routerRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		link, err := AcceptRouteControlLink(
			ctx,
			routerRaw,
			routerID,
			store,
			mesh.TransportInternet,
		)
		if link != nil {
			_ = link.Close()
		}
		serverDone <- err
	}()

	link, _ := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Transport:   mesh.TransportInternet,
		},
	)
	if link != nil {
		_ = link.Close()
	}

	err = <-serverDone
	if !errors.Is(err, ErrNeighborIdentityMismatch) {
		t.Fatalf(
			"AcceptRouteControlLink() error = %v, want ErrNeighborIdentityMismatch",
			err,
		)
	}
}

func TestMeshALPNDoesNotNegotiateEndpointSessionProtocol(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	serverID := testIdentity(t, "server")

	clientRaw, serverRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		conn := tls.Server(serverRaw, identity.ServerTLS(serverID))
		err := conn.HandshakeContext(ctx)
		_ = conn.Close()
		serverDone <- err
	}()

	link, err := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(serverID.ID),
			Fingerprint: fingerprintForIdentity(t, serverID),
			Transport:   mesh.TransportLAN,
		},
	)
	if link != nil {
		_ = link.Close()
	}
	if err == nil {
		t.Fatal("mesh TLS unexpectedly negotiated endpoint session TLS")
	}

	<-serverDone
}

func TestDialTrustedLinkHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")

	clientRaw, routerRaw := testTCPPair(t)
	defer routerRaw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	link, err := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Transport:   mesh.TransportLAN,
		},
	)
	if link != nil {
		_ = link.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialRouteControlLink() error = %v, want context.Canceled", err)
	}
}

func TestServerTrustRejectionStaysLocal(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	routerTrust := testNeighborStore(t)

	clientRaw, routerRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type serverResult struct {
		link *TLSLink
		err  error
	}
	serverDone := make(chan serverResult, 1)

	go func() {
		link, err := AcceptRouteControlLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportLAN,
		)
		serverDone <- serverResult{link: link, err: err}
	}()

	clientLink, clientErr := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Transport:   mesh.TransportLAN,
		},
	)

	server := <-serverDone
	if server.link != nil {
		_ = server.link.Close()
		t.Fatal("server returned a usable link for an untrusted neighbor")
	}
	if !errors.Is(server.err, ErrNeighborUntrusted) {
		t.Fatalf(
			"server error = %v, want ErrNeighborUntrusted",
			server.err,
		)
	}

	assertRemoteRejectionDoesNotLeakSentinel(
		t,
		clientLink,
		clientErr,
	)
}

func TestServerFingerprintRejectionStaysLocal(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	otherID := testIdentity(t, "other")

	store, err := trust.Open(filepath.Join(t.TempDir(), "router-peers.json"))
	if err != nil {
		t.Fatalf("trust.Open() error: %v", err)
	}
	if err := store.Put(trust.Peer{
		ID:          clientID.ID,
		Fingerprint: fingerprintForIdentity(t, otherID),
	}); err != nil {
		t.Fatalf("Store.Put() error: %v", err)
	}

	clientRaw, routerRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type serverResult struct {
		link *TLSLink
		err  error
	}
	serverDone := make(chan serverResult, 1)

	go func() {
		link, err := AcceptRouteControlLink(
			ctx,
			routerRaw,
			routerID,
			store,
			mesh.TransportInternet,
		)
		serverDone <- serverResult{link: link, err: err}
	}()

	clientLink, clientErr := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Transport:   mesh.TransportInternet,
		},
	)

	server := <-serverDone
	if server.link != nil {
		_ = server.link.Close()
		t.Fatal("server returned a usable link after fingerprint rejection")
	}
	if !errors.Is(server.err, ErrNeighborIdentityMismatch) {
		t.Fatalf(
			"server error = %v, want ErrNeighborIdentityMismatch",
			server.err,
		)
	}

	assertRemoteRejectionDoesNotLeakSentinel(
		t,
		clientLink,
		clientErr,
	)
}

func assertRemoteRejectionDoesNotLeakSentinel(
	t *testing.T,
	link *TLSLink,
	handshakeErr error,
) {
	t.Helper()

	if handshakeErr != nil {
		if errors.Is(handshakeErr, ErrNeighborUntrusted) ||
			errors.Is(handshakeErr, ErrNeighborIdentityMismatch) {
			t.Fatalf(
				"remote peer received local trust sentinel: %v",
				handshakeErr,
			)
		}
		if link != nil {
			_ = link.Close()
			t.Fatal("failed handshake returned a non-nil link")
		}
		return
	}

	// TLS 1.3 can let this side finish its handshake before the peer's
	// client-certificate verification failure is observed. That does not make
	// the connection usable: the rejecting side never returns a TLSLink and
	// closes the TLS connection. Confirm the remote stream subsequently fails
	// without receiving our process-local trust sentinels.
	if link == nil {
		t.Fatal("successful handshake returned a nil link")
	}
	defer link.Close()

	if err := link.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error: %v", err)
	}

	var one [1]byte
	_, err := link.Read(one[:])
	if err == nil {
		t.Fatal("remote link remained readable after peer rejected authentication")
	}
	if errors.Is(err, ErrNeighborUntrusted) ||
		errors.Is(err, ErrNeighborIdentityMismatch) {
		t.Fatalf(
			"remote stream leaked local trust sentinel: %v",
			err,
		)
	}
}

func TestClientPinningRejectionStaysLocal(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	otherID := testIdentity(t, "other")
	routerTrust := testNeighborStore(t, clientID)

	clientRaw, routerRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		link, err := AcceptRouteControlLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportInternet,
		)
		if link != nil {
			_ = link.Close()
		}
		serverDone <- err
	}()

	clientLink, clientErr := DialRouteControlLink(
		ctx,
		clientRaw,
		clientID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, otherID),
			Transport:   mesh.TransportInternet,
		},
	)
	if clientLink != nil {
		_ = clientLink.Close()
	}

	if !errors.Is(clientErr, ErrNeighborIdentityMismatch) {
		t.Fatalf(
			"client error = %v, want ErrNeighborIdentityMismatch",
			clientErr,
		)
	}

	serverErr := <-serverDone
	if serverErr == nil {
		t.Fatal("server unexpectedly completed handshake after client pinning rejection")
	}
	if errors.Is(serverErr, ErrNeighborUntrusted) ||
		errors.Is(serverErr, ErrNeighborIdentityMismatch) {
		t.Fatalf(
			"remote server received client-local identity sentinel: %v",
			serverErr,
		)
	}
}

func TestRouteTunnelLinkAuthenticatesTrustedNeighbors(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")
	destinationTrust := testNeighborStore(t, routerID)

	routerRaw, destinationRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type acceptResult struct {
		link *TLSLink
		err  error
	}
	accepted := make(chan acceptResult, 1)

	go func() {
		link, err := AcceptRouteTunnelLink(
			ctx,
			destinationRaw,
			destinationID,
			destinationTrust,
			mesh.TransportInternet,
		)
		accepted <- acceptResult{link: link, err: err}
	}()

	routerLink, err := DialRouteTunnelLink(
		ctx,
		routerRaw,
		routerID,
		ResolvedPeer{
			ID:          mesh.DeviceID(destinationID.ID),
			Fingerprint: fingerprintForIdentity(t, destinationID),
			Transport:   mesh.TransportInternet,
		},
	)
	if err != nil {
		t.Fatalf("DialRouteTunnelLink() error: %v", err)
	}
	defer routerLink.Close()

	result := <-accepted
	if result.err != nil {
		t.Fatalf("AcceptRouteTunnelLink() error: %v", result.err)
	}
	defer result.link.Close()

	if routerLink.Remote() != mesh.DeviceID(destinationID.ID) {
		t.Fatalf(
			"router remote = %q, want %q",
			routerLink.Remote(),
			destinationID.ID,
		)
	}
	if result.link.Remote() != mesh.DeviceID(routerID.ID) {
		t.Fatalf(
			"destination remote = %q, want %q",
			result.link.Remote(),
			routerID.ID,
		)
	}

	want := []byte("opaque-inner-endpoint-tls")
	writeDone := make(chan error, 1)
	go func() {
		_, err := routerLink.Write(want)
		writeDone <- err
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(result.link, got); err != nil {
		t.Fatalf("ReadFull() error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("Write() error: %v", err)
	}
}

func TestMeshRouteRolesDoNotCrossNegotiate(t *testing.T) {
	t.Parallel()

	sourceID := testIdentity(t, "source")
	routerID := testIdentity(t, "router")
	routerTrust := testNeighborStore(t, sourceID)

	sourceRaw, routerRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type acceptResult struct {
		link *TLSLink
		err  error
	}
	accepted := make(chan acceptResult, 1)

	go func() {
		link, err := AcceptRouteTunnelLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportLAN,
		)
		accepted <- acceptResult{link: link, err: err}
	}()

	sourceLink, sourceErr := DialRouteControlLink(
		ctx,
		sourceRaw,
		sourceID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Transport:   mesh.TransportLAN,
		},
	)
	if sourceLink != nil {
		_ = sourceLink.Close()
		t.Fatal("route-control peer negotiated destination-tunnel role")
	}
	if sourceErr == nil {
		t.Fatal("route-control/tunnel ALPN mismatch unexpectedly succeeded")
	}

	result := <-accepted
	if result.link != nil {
		_ = result.link.Close()
		t.Fatal("tunnel listener accepted route-control role")
	}
	if result.err == nil {
		t.Fatal("tunnel listener accepted mismatched ALPN")
	}
}

func TestMeshRouteRolesDoNotCrossNegotiateReverse(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")
	routerTrust := testNeighborStore(t, destinationID)

	routerRaw, destinationRaw := testTCPPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type acceptResult struct {
		link *TLSLink
		err  error
	}
	accepted := make(chan acceptResult, 1)

	go func() {
		link, err := AcceptRouteControlLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportInternet,
		)
		accepted <- acceptResult{link: link, err: err}
	}()

	destinationLink, destinationErr := DialRouteTunnelLink(
		ctx,
		destinationRaw,
		destinationID,
		ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Transport:   mesh.TransportInternet,
		},
	)
	if destinationLink != nil {
		_ = destinationLink.Close()
		t.Fatal("tunnel peer negotiated route-control role")
	}
	if destinationErr == nil {
		t.Fatal("tunnel/route-control ALPN mismatch unexpectedly succeeded")
	}

	result := <-accepted
	if result.link != nil {
		_ = result.link.Close()
		t.Fatal("route-control listener accepted tunnel role")
	}
	if result.err == nil {
		t.Fatal("route-control listener accepted mismatched ALPN")
	}
}

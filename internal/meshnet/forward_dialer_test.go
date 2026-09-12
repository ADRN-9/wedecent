package meshnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

func TestForwardDialerAuthenticatesDestinationTunnel(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")
	destinationTrust := testNeighborStore(t, routerID)

	routerRaw, destinationRaw := testTCPPair(t)

	resolver := &staticPeerResolver{
		peer: ResolvedPeer{
			ID:          mesh.DeviceID(destinationID.ID),
			Fingerprint: fingerprintForIdentity(t, destinationID),
			Locator:     "tcp://127.0.0.1:7443",
			Transport:   mesh.TransportInternet,
		},
	}

	dialedAddress := ""
	dialer := ForwardDialer{
		Identity: routerID,
		Resolver: resolver,
		DialTCP: func(
			_ context.Context,
			address string,
		) (net.Conn, error) {
			dialedAddress = address
			return routerRaw, nil
		},
	}

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

	outgoing, err := dialer.DialNext(
		ctx,
		mesh.RouteHop{
			From:      mesh.DeviceID(routerID.ID),
			To:        mesh.DeviceID(destinationID.ID),
			Transport: mesh.TransportInternet,
		},
	)
	if err != nil {
		t.Fatalf("DialNext() error: %v", err)
	}
	defer outgoing.Close()

	result := <-accepted
	if result.err != nil {
		t.Fatalf("AcceptRouteTunnelLink() error: %v", result.err)
	}
	defer result.link.Close()

	if dialedAddress != "127.0.0.1:7443" {
		t.Fatalf(
			"dialed address = %q, want resolver-owned address",
			dialedAddress,
		)
	}

	if resolver.calls != 1 ||
		resolver.lastID != mesh.DeviceID(destinationID.ID) ||
		resolver.lastTransport != mesh.TransportInternet {
		t.Fatalf(
			"resolver calls=%d id=%q transport=%q",
			resolver.calls,
			resolver.lastID,
			resolver.lastTransport,
		)
	}

	if outgoing.Local() != mesh.DeviceID(routerID.ID) ||
		outgoing.Remote() != mesh.DeviceID(destinationID.ID) ||
		outgoing.Transport() != mesh.TransportInternet {
		t.Fatalf(
			"unexpected outgoing link: local=%q remote=%q transport=%q",
			outgoing.Local(),
			outgoing.Remote(),
			outgoing.Transport(),
		)
	}

	const request = "opaque-inner-endpoint-tls-request"
	const response = "opaque-inner-endpoint-tls-response"

	destinationDone := make(chan error, 1)
	go func() {
		requestBuf := make([]byte, len(request))
		if _, err := io.ReadFull(result.link, requestBuf); err != nil {
			destinationDone <- fmt.Errorf("read request: %w", err)
			return
		}
		if string(requestBuf) != request {
			destinationDone <- fmt.Errorf(
				"request = %q, want %q",
				requestBuf,
				request,
			)
			return
		}

		if _, err := result.link.Write([]byte(response)); err != nil {
			destinationDone <- fmt.Errorf("write response: %w", err)
			return
		}

		destinationDone <- nil
	}()

	if _, err := outgoing.Write([]byte(request)); err != nil {
		t.Fatalf("outgoing.Write() error: %v", err)
	}

	responseBuf := make([]byte, len(response))
	if _, err := io.ReadFull(outgoing, responseBuf); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(responseBuf) != response {
		t.Fatalf(
			"response = %q, want %q",
			responseBuf,
			response,
		)
	}

	if err := <-destinationDone; err != nil {
		t.Fatal(err)
	}
}

func TestForwardDialerRejectsWrongLocalHopBeforeResolution(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	sourceID := testIdentity(t, "source")
	destinationID := testIdentity(t, "destination")

	resolver := &staticPeerResolver{}

	dialer := ForwardDialer{
		Identity: routerID,
		Resolver: resolver,
		DialTCP: func(
			context.Context,
			string,
		) (net.Conn, error) {
			return nil, errors.New("network dial must not run")
		},
	}

	link, err := dialer.DialNext(
		context.Background(),
		mesh.RouteHop{
			From:      mesh.DeviceID(sourceID.ID),
			To:        mesh.DeviceID(destinationID.ID),
			Transport: mesh.TransportInternet,
		},
	)
	if link != nil {
		_ = link.Close()
		t.Fatal("wrong-source hop returned a link")
	}
	if !errors.Is(err, ErrForwardHopInvalid) {
		t.Fatalf(
			"DialNext() error = %v, want ErrForwardHopInvalid",
			err,
		)
	}
	if resolver.calls != 0 {
		t.Fatalf(
			"resolver called %d time(s) for invalid hop",
			resolver.calls,
		)
	}
}

func TestForwardDialerRejectsSelfHopBeforeResolution(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	resolver := &staticPeerResolver{}

	dialer := ForwardDialer{
		Identity: routerID,
		Resolver: resolver,
	}

	link, err := dialer.DialNext(
		context.Background(),
		mesh.RouteHop{
			From:      mesh.DeviceID(routerID.ID),
			To:        mesh.DeviceID(routerID.ID),
			Transport: mesh.TransportLAN,
		},
	)
	if link != nil {
		_ = link.Close()
		t.Fatal("self-hop returned a link")
	}
	if !errors.Is(err, ErrForwardHopInvalid) {
		t.Fatalf(
			"DialNext() error = %v, want ErrForwardHopInvalid",
			err,
		)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver called %d time(s)", resolver.calls)
	}
}

func TestForwardDialerRejectsResolverIdentityMismatchBeforeNetwork(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")
	wrongID := testIdentity(t, "wrong-destination")

	resolver := &staticPeerResolver{
		peer: ResolvedPeer{
			ID:          mesh.DeviceID(wrongID.ID),
			Fingerprint: fingerprintForIdentity(t, wrongID),
			Locator:     "tcp://127.0.0.1:7443",
			Transport:   mesh.TransportInternet,
		},
	}

	dialCalls := 0
	dialer := ForwardDialer{
		Identity: routerID,
		Resolver: resolver,
		DialTCP: func(
			context.Context,
			string,
		) (net.Conn, error) {
			dialCalls++
			return nil, errors.New("network dial must not run")
		},
	}

	link, err := dialer.DialNext(
		context.Background(),
		mesh.RouteHop{
			From:      mesh.DeviceID(routerID.ID),
			To:        mesh.DeviceID(destinationID.ID),
			Transport: mesh.TransportInternet,
		},
	)
	if link != nil {
		_ = link.Close()
		t.Fatal("mismatched resolver returned a link")
	}
	if !errors.Is(err, ErrForwardPeerMismatch) {
		t.Fatalf(
			"DialNext() error = %v, want ErrForwardPeerMismatch",
			err,
		)
	}
	if dialCalls != 0 {
		t.Fatalf("network dial called %d time(s)", dialCalls)
	}
}

func TestForwardDialerRejectsResolverTransportMismatchBeforeNetwork(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")

	resolver := &staticPeerResolver{
		peer: ResolvedPeer{
			ID:          mesh.DeviceID(destinationID.ID),
			Fingerprint: fingerprintForIdentity(t, destinationID),
			Locator:     "tcp://127.0.0.1:7443",
			Transport:   mesh.TransportLAN,
		},
	}

	dialCalls := 0
	dialer := ForwardDialer{
		Identity: routerID,
		Resolver: resolver,
		DialTCP: func(
			context.Context,
			string,
		) (net.Conn, error) {
			dialCalls++
			return nil, errors.New("network dial must not run")
		},
	}

	link, err := dialer.DialNext(
		context.Background(),
		mesh.RouteHop{
			From:      mesh.DeviceID(routerID.ID),
			To:        mesh.DeviceID(destinationID.ID),
			Transport: mesh.TransportInternet,
		},
	)
	if link != nil {
		_ = link.Close()
		t.Fatal("transport-mismatched resolver returned a link")
	}
	if !errors.Is(err, ErrForwardPeerMismatch) {
		t.Fatalf(
			"DialNext() error = %v, want ErrForwardPeerMismatch",
			err,
		)
	}
	if dialCalls != 0 {
		t.Fatalf("network dial called %d time(s)", dialCalls)
	}
}

func TestForwardDialerPropagatesResolverFailureBeforeNetwork(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")

	resolverErr := errors.New("resolver failed closed")
	resolver := &staticPeerResolver{
		err: resolverErr,
	}

	dialCalls := 0
	dialer := ForwardDialer{
		Identity: routerID,
		Resolver: resolver,
		DialTCP: func(
			context.Context,
			string,
		) (net.Conn, error) {
			dialCalls++
			return nil, errors.New("network dial must not run")
		},
	}

	link, err := dialer.DialNext(
		context.Background(),
		mesh.RouteHop{
			From:      mesh.DeviceID(routerID.ID),
			To:        mesh.DeviceID(destinationID.ID),
			Transport: mesh.TransportInternet,
		},
	)
	if link != nil {
		_ = link.Close()
		t.Fatal("resolver failure returned a link")
	}
	if !errors.Is(err, resolverErr) {
		t.Fatalf(
			"DialNext() error = %v, want resolver error",
			err,
		)
	}
	if dialCalls != 0 {
		t.Fatalf("network dial called %d time(s)", dialCalls)
	}
}

func TestForwardDialerPinsDestinationIdentity(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")
	wrongPinnedID := testIdentity(t, "wrong-pin")

	destinationTrust := testNeighborStore(t, routerID)
	routerRaw, destinationRaw := testTCPPair(t)

	resolver := &staticPeerResolver{
		peer: ResolvedPeer{
			ID:          mesh.DeviceID(destinationID.ID),
			Fingerprint: fingerprintForIdentity(t, wrongPinnedID),
			Locator:     "tcp://127.0.0.1:7443",
			Transport:   mesh.TransportInternet,
		},
	}

	dialer := ForwardDialer{
		Identity: routerID,
		Resolver: resolver,
		DialTCP: func(
			context.Context,
			string,
		) (net.Conn, error) {
			return routerRaw, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		link, err := AcceptRouteTunnelLink(
			ctx,
			destinationRaw,
			destinationID,
			destinationTrust,
			mesh.TransportInternet,
		)
		if link != nil {
			_ = link.Close()
		}
		serverDone <- err
	}()

	link, err := dialer.DialNext(
		ctx,
		mesh.RouteHop{
			From:      mesh.DeviceID(routerID.ID),
			To:        mesh.DeviceID(destinationID.ID),
			Transport: mesh.TransportInternet,
		},
	)
	if link != nil {
		_ = link.Close()
		t.Fatal("wrong pinned fingerprint returned a link")
	}
	if !errors.Is(err, ErrNeighborIdentityMismatch) {
		t.Fatalf(
			"DialNext() error = %v, want ErrNeighborIdentityMismatch",
			err,
		)
	}

	// The remote side may report only a generic TLS failure, depending on the
	// TLS 1.3 handshake timing. It must terminate rather than yielding a usable
	// destination link.
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("destination did not observe failed TLS link")
	}
}

func TestForwardDialerHonorsCanceledContextBeforeResolution(t *testing.T) {
	t.Parallel()

	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")
	resolver := &staticPeerResolver{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dialer := ForwardDialer{
		Identity: routerID,
		Resolver: resolver,
	}

	link, err := dialer.DialNext(
		ctx,
		mesh.RouteHop{
			From:      mesh.DeviceID(routerID.ID),
			To:        mesh.DeviceID(destinationID.ID),
			Transport: mesh.TransportInternet,
		},
	)
	if link != nil {
		_ = link.Close()
		t.Fatal("canceled dial returned a link")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"DialNext() error = %v, want context.Canceled",
			err,
		)
	}
	if resolver.calls != 0 {
		t.Fatalf(
			"resolver called %d time(s) after cancellation",
			resolver.calls,
		)
	}
}

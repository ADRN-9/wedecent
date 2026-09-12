package meshnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
)

type staticPeerResolver struct {
	peer          ResolvedPeer
	err           error
	calls         int
	lastID        mesh.DeviceID
	lastTransport mesh.TransportName
}

func (r *staticPeerResolver) Resolve(
	_ context.Context,
	id mesh.DeviceID,
	transportName mesh.TransportName,
) (ResolvedPeer, error) {
	r.calls++
	r.lastID = id
	r.lastTransport = transportName

	if r.err != nil {
		return ResolvedPeer{}, r.err
	}
	return r.peer, nil
}

func testOneHopRoute(
	clientID *identity.Identity,
	routerID *identity.Identity,
	destinationID *identity.Identity,
) mesh.Route {
	return mesh.Route{
		ID:          "route-a-b-c",
		Source:      mesh.DeviceID(clientID.ID),
		Destination: mesh.DeviceID(destinationID.ID),
		ExpiresAt:   time.Now().Add(time.Minute),
		Hops: []mesh.RouteHop{
			{
				From:      mesh.DeviceID(clientID.ID),
				To:        mesh.DeviceID(routerID.ID),
				Transport: mesh.TransportLAN,
			},
			{
				From:      mesh.DeviceID(routerID.ID),
				To:        mesh.DeviceID(destinationID.ID),
				Transport: mesh.TransportInternet,
			},
		},
	}
}

func TestRoutedDialerAcceptedRouteBecomesOpaqueTunnel(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")

	routerTrust := testNeighborStore(t, clientID)
	clientRaw, routerRaw := testTCPPair(t)

	route := testOneHopRoute(clientID, routerID, destinationID)

	resolver := &staticPeerResolver{
		peer: ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Locator:     "tcp://127.0.0.1:7443",
			Transport:   mesh.TransportLAN,
		},
	}

	dialedAddress := ""
	dialer := RoutedDialer{
		Identity: clientID,
		Resolver: resolver,
		Route:    route,
		DialTCP: func(
			_ context.Context,
			address string,
		) (net.Conn, error) {
			dialedAddress = address
			return clientRaw, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		link, err := AcceptTrustedLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportLAN,
		)
		if err != nil {
			serverDone <- fmt.Errorf("AcceptTrustedLink: %w", err)
			return
		}
		defer link.Close()

		req, err := mesh.ReadRouteOpenRequest(link)
		if err != nil {
			serverDone <- fmt.Errorf("ReadRouteOpenRequest: %w", err)
			return
		}

		if req.Route.ID != route.ID ||
			req.Route.Source != route.Source ||
			req.Route.Destination != route.Destination ||
			len(req.Route.Hops) != 2 {
			serverDone <- fmt.Errorf("unexpected route: %+v", req.Route)
			return
		}

		if err := mesh.WriteRouteOpenResponse(
			link,
			mesh.RouteOpenResponse{Accepted: true},
		); err != nil {
			serverDone <- fmt.Errorf("WriteRouteOpenResponse: %w", err)
			return
		}

		want := []byte("inner-endpoint-tls")
		got := make([]byte, len(want))
		if _, err := io.ReadFull(link, got); err != nil {
			serverDone <- fmt.Errorf("read tunnel bytes: %w", err)
			return
		}
		if string(got) != string(want) {
			serverDone <- fmt.Errorf(
				"tunnel bytes = %q, want %q",
				got,
				want,
			)
			return
		}

		serverDone <- nil
	}()

	// Deliberately attacker-looking input. RoutedDialer must not use the
	// session endpoint argument as the router network target.
	conn, err := dialer.Dial(
		ctx,
		"tcp://203.0.113.250:65535",
	)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	if dialedAddress != "127.0.0.1:7443" {
		t.Fatalf(
			"dialed address = %q, want trusted resolver address",
			dialedAddress,
		)
	}

	if resolver.calls != 1 ||
		resolver.lastID != mesh.DeviceID(routerID.ID) ||
		resolver.lastTransport != mesh.TransportLAN {
		t.Fatalf(
			"resolver calls=%d id=%q transport=%q",
			resolver.calls,
			resolver.lastID,
			resolver.lastTransport,
		)
	}

	if _, err := conn.Write([]byte("inner-endpoint-tls")); err != nil {
		t.Fatalf("tunnel Write() error: %v", err)
	}

	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestRoutedDialerReturnsStableRouteRejection(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")

	routerTrust := testNeighborStore(t, clientID)
	clientRaw, routerRaw := testTCPPair(t)

	route := testOneHopRoute(clientID, routerID, destinationID)

	resolver := &staticPeerResolver{
		peer: ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Locator:     "tcp://127.0.0.1:7443",
			Transport:   mesh.TransportLAN,
		},
	}

	dialer := RoutedDialer{
		Identity: clientID,
		Resolver: resolver,
		Route:    route,
		DialTCP: func(
			context.Context,
			string,
		) (net.Conn, error) {
			return clientRaw, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		link, err := AcceptTrustedLink(
			ctx,
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportLAN,
		)
		if err != nil {
			serverDone <- err
			return
		}
		defer link.Close()

		if _, err := mesh.ReadRouteOpenRequest(link); err != nil {
			serverDone <- err
			return
		}

		serverDone <- mesh.WriteRouteOpenResponse(
			link,
			mesh.RouteOpenResponse{
				Accepted: false,
				Code:     mesh.RouteOpenCodeDenied,
			},
		)
	}()

	conn, err := dialer.Dial(ctx, "ignored")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("rejected route returned a connection")
	}
	if !errors.Is(err, ErrRouteRejected) {
		t.Fatalf("Dial() error = %v, want ErrRouteRejected", err)
	}

	var rejected *RouteRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("Dial() error = %v, want RouteRejectedError", err)
	}
	if rejected.Code != mesh.RouteOpenCodeDenied {
		t.Fatalf(
			"rejection code = %q, want %q",
			rejected.Code,
			mesh.RouteOpenCodeDenied,
		)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("router error: %v", err)
	}
}

func TestRoutedDialerRejectsInvalidRouteBeforeResolution(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")

	resolver := &staticPeerResolver{}

	dialer := RoutedDialer{
		Identity: clientID,
		Resolver: resolver,
		Route: mesh.Route{
			ID:          "not-one-hop",
			Source:      mesh.DeviceID(clientID.ID),
			Destination: mesh.DeviceID(routerID.ID),
			ExpiresAt:   time.Now().Add(time.Minute),
			Hops: []mesh.RouteHop{
				{
					From:      mesh.DeviceID(clientID.ID),
					To:        mesh.DeviceID(routerID.ID),
					Transport: mesh.TransportLAN,
				},
			},
		},
		DialTCP: func(
			context.Context,
			string,
		) (net.Conn, error) {
			return nil, errors.New("dial must not be called")
		},
	}

	conn, err := dialer.Dial(context.Background(), "ignored")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("invalid route returned a connection")
	}
	if !errors.Is(err, ErrRoutedRouteInvalid) {
		t.Fatalf(
			"Dial() error = %v, want ErrRoutedRouteInvalid",
			err,
		)
	}
	if resolver.calls != 0 {
		t.Fatalf(
			"resolver called %d time(s) for invalid route",
			resolver.calls,
		)
	}
}

func TestRoutedDialerRejectsWrongLocalSourceBeforeResolution(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	otherID := testIdentity(t, "other")
	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")

	route := testOneHopRoute(otherID, routerID, destinationID)
	resolver := &staticPeerResolver{}

	dialer := RoutedDialer{
		Identity: clientID,
		Resolver: resolver,
		Route:    route,
	}

	conn, err := dialer.Dial(context.Background(), "ignored")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("wrong-source route returned a connection")
	}
	if !errors.Is(err, ErrRoutedRouteInvalid) {
		t.Fatalf(
			"Dial() error = %v, want ErrRoutedRouteInvalid",
			err,
		)
	}
	if resolver.calls != 0 {
		t.Fatalf(
			"resolver called %d time(s) for wrong-source route",
			resolver.calls,
		)
	}
}

func TestRoutedDialerRejectsResolverMismatchBeforeNetworkDial(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	otherRouterID := testIdentity(t, "other-router")
	destinationID := testIdentity(t, "destination")

	route := testOneHopRoute(clientID, routerID, destinationID)

	resolver := &staticPeerResolver{
		peer: ResolvedPeer{
			ID:          mesh.DeviceID(otherRouterID.ID),
			Fingerprint: fingerprintForIdentity(t, otherRouterID),
			Locator:     "tcp://127.0.0.1:7443",
			Transport:   mesh.TransportLAN,
		},
	}

	dialCalls := 0
	dialer := RoutedDialer{
		Identity: clientID,
		Resolver: resolver,
		Route:    route,
		DialTCP: func(
			context.Context,
			string,
		) (net.Conn, error) {
			dialCalls++
			return nil, errors.New("must not dial")
		},
	}

	conn, err := dialer.Dial(context.Background(), "ignored")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("mismatched resolver returned a connection")
	}
	if !errors.Is(err, ErrRoutedPeerMismatch) {
		t.Fatalf(
			"Dial() error = %v, want ErrRoutedPeerMismatch",
			err,
		)
	}
	if dialCalls != 0 {
		t.Fatalf("network dial called %d time(s)", dialCalls)
	}
}

func TestRoutedDialerCancellationInterruptsRouteOpenRead(t *testing.T) {
	t.Parallel()

	clientID := testIdentity(t, "client")
	routerID := testIdentity(t, "router")
	destinationID := testIdentity(t, "destination")

	routerTrust := testNeighborStore(t, clientID)
	clientRaw, routerRaw := testTCPPair(t)

	route := testOneHopRoute(clientID, routerID, destinationID)

	resolver := &staticPeerResolver{
		peer: ResolvedPeer{
			ID:          mesh.DeviceID(routerID.ID),
			Fingerprint: fingerprintForIdentity(t, routerID),
			Locator:     "tcp://127.0.0.1:7443",
			Transport:   mesh.TransportLAN,
		},
	}

	dialer := RoutedDialer{
		Identity: clientID,
		Resolver: resolver,
		Route:    route,
		DialTCP: func(
			context.Context,
			string,
		) (net.Conn, error) {
			return clientRaw, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	requestRead := make(chan struct{})
	serverDone := make(chan error, 1)

	go func() {
		link, err := AcceptTrustedLink(
			context.Background(),
			routerRaw,
			routerID,
			routerTrust,
			mesh.TransportLAN,
		)
		if err != nil {
			serverDone <- err
			return
		}
		defer link.Close()

		if _, err := mesh.ReadRouteOpenRequest(link); err != nil {
			serverDone <- err
			return
		}

		close(requestRead)

		var one [1]byte
		_, err = link.Read(one[:])
		serverDone <- err
	}()

	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)

	go func() {
		conn, err := dialer.Dial(ctx, "ignored")
		resultCh <- dialResult{conn: conn, err: err}
	}()

	select {
	case <-requestRead:
	case <-time.After(2 * time.Second):
		t.Fatal("router did not receive route-open request")
	}

	cancel()

	select {
	case result := <-resultCh:
		if result.conn != nil {
			_ = result.conn.Close()
			t.Fatal("canceled route-open returned a connection")
		}
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf(
				"Dial() error = %v, want context.Canceled",
				result.err,
			)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Dial() did not unblock after cancellation")
	}

	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("router side did not observe canceled connection")
	}
}

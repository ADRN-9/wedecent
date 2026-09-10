package mesh

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type testMeshLink struct {
	net.Conn
	local     DeviceID
	remote    DeviceID
	transport TransportName
}

func (l *testMeshLink) Local() DeviceID          { return l.local }
func (l *testMeshLink) Remote() DeviceID         { return l.remote }
func (l *testMeshLink) Transport() TransportName { return l.transport }

type forwardAuthorizerFunc func(context.Context, ForwardRequest) error

func (f forwardAuthorizerFunc) AuthorizeForward(ctx context.Context, req ForwardRequest) error {
	return f(ctx, req)
}

func oneHopTestRoute(expires time.Time) Route {
	return Route{
		ID:          "route-a-b-c",
		Source:      "wd_a",
		Destination: "wd_c",
		ExpiresAt:   expires,
		Hops: []RouteHop{
			{
				From:      "wd_a",
				To:        "wd_b",
				Transport: TransportLAN,
			},
			{
				From:      "wd_b",
				To:        "wd_c",
				Transport: TransportInternet,
			},
		},
	}
}

func TestForwarderCopiesOpaqueBytes(t *testing.T) {
	t.Parallel()

	clientSide, routerIncomingConn := net.Pipe()
	routerOutgoingConn, targetSide := net.Pipe()

	defer clientSide.Close()
	defer targetSide.Close()

	incoming := &testMeshLink{
		Conn:      routerIncomingConn,
		local:     "wd_b",
		remote:    "wd_a",
		transport: TransportLAN,
	}
	outgoing := &testMeshLink{
		Conn:      routerOutgoingConn,
		local:     "wd_b",
		remote:    "wd_c",
		transport: TransportInternet,
	}

	var authorized atomic.Bool

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
			MaxSessions:        1,
		},
		Authorizer: forwardAuthorizerFunc(func(_ context.Context, req ForwardRequest) error {
			if req.Router != "wd_b" {
				t.Errorf("router = %q, want wd_b", req.Router)
			}
			if req.Route.Source != "wd_a" || req.Route.Destination != "wd_c" {
				t.Errorf("unexpected authorization route: %+v", req.Route)
			}
			authorized.Store(true)
			return nil
		}),
		DialNext: func(_ context.Context, hop RouteHop) (Link, error) {
			if hop.From != "wd_b" || hop.To != "wd_c" {
				t.Errorf("unexpected outgoing hop: %+v", hop)
			}
			return outgoing, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type forwardResponse struct {
		result ForwardResult
		err    error
	}
	forwardDone := make(chan forwardResponse, 1)

	go func() {
		result, err := forwarder.Forward(ctx, oneHopTestRoute(time.Now().Add(time.Minute)), incoming)
		forwardDone <- forwardResponse{result: result, err: err}
	}()

	const request = "opaque-inner-tls-request"
	const response = "opaque-inner-tls-response"

	targetDone := make(chan error, 1)
	go func() {
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(targetSide, buf); err != nil {
			targetDone <- err
			return
		}
		if string(buf) != request {
			targetDone <- errors.New("target received altered bytes")
			return
		}
		if _, err := targetSide.Write([]byte(response)); err != nil {
			targetDone <- err
			return
		}
		targetDone <- nil
	}()

	if _, err := clientSide.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	buf := make([]byte, len(response))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(buf) != response {
		t.Fatalf("response = %q, want %q", buf, response)
	}

	if err := <-targetDone; err != nil {
		t.Fatalf("target exchange: %v", err)
	}

	_ = clientSide.Close()

	got := <-forwardDone
	if got.err != nil {
		t.Fatalf("Forward() error: %v", got.err)
	}
	if !authorized.Load() {
		t.Fatal("forwarding occurred without authorization")
	}
	if got.result.BytesToDestination != int64(len(request)) {
		t.Fatalf("BytesToDestination = %d, want %d", got.result.BytesToDestination, len(request))
	}
	if got.result.BytesToSource != int64(len(response)) {
		t.Fatalf("BytesToSource = %d, want %d", got.result.BytesToSource, len(response))
	}
}

func TestForwarderFailsClosedWhenRoutingDisabled(t *testing.T) {
	t.Parallel()

	routerSide, peerSide := net.Pipe()
	defer peerSide.Close()

	var authorized atomic.Bool
	var dialed atomic.Bool

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy:  DisabledRouterPolicy(),
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			authorized.Store(true)
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			dialed.Store(true)
			return nil, nil
		},
	}

	_, err := forwarder.Forward(
		context.Background(),
		oneHopTestRoute(time.Now().Add(time.Minute)),
		&testMeshLink{
			Conn:      routerSide,
			local:     "wd_b",
			remote:    "wd_a",
			transport: TransportLAN,
		},
	)
	if !errors.Is(err, ErrRoutingDisabled) {
		t.Fatalf("Forward() error = %v, want ErrRoutingDisabled", err)
	}
	if authorized.Load() {
		t.Fatal("disabled router invoked authorizer")
	}
	if dialed.Load() {
		t.Fatal("disabled router dialed destination")
	}

	_ = peerSide.SetReadDeadline(time.Now().Add(time.Second))
	if _, readErr := peerSide.Read(make([]byte, 1)); !errors.Is(readErr, io.EOF) {
		t.Fatalf("rejected incoming link read error = %v, want EOF", readErr)
	}
}

func TestForwarderRejectsUnauthorizedRouteBeforeDial(t *testing.T) {
	t.Parallel()

	routerSide, peerSide := net.Pipe()
	defer routerSide.Close()
	defer peerSide.Close()

	var dialed atomic.Bool

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			return errors.New("denied")
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			dialed.Store(true)
			return nil, nil
		},
	}

	_, err := forwarder.Forward(
		context.Background(),
		oneHopTestRoute(time.Now().Add(time.Minute)),
		&testMeshLink{
			Conn:      routerSide,
			local:     "wd_b",
			remote:    "wd_a",
			transport: TransportLAN,
		},
	)
	if !errors.Is(err, ErrForwardDenied) {
		t.Fatalf("Forward() error = %v, want ErrForwardDenied", err)
	}
	if dialed.Load() {
		t.Fatal("unauthorized route dialed destination")
	}

	_ = peerSide.SetReadDeadline(time.Now().Add(time.Second))
	if _, readErr := peerSide.Read(make([]byte, 1)); !errors.Is(readErr, io.EOF) {
		t.Fatalf("unauthorized incoming link read error = %v, want EOF", readErr)
	}
}

func TestForwarderRequiresExactOneHopRoute(t *testing.T) {
	t.Parallel()

	routerSide, peerSide := net.Pipe()
	defer routerSide.Close()
	defer peerSide.Close()

	route := Route{
		ID:          "direct",
		Source:      "wd_a",
		Destination: "wd_b",
		ExpiresAt:   time.Now().Add(time.Minute),
		Hops: []RouteHop{{
			From:      "wd_a",
			To:        "wd_b",
			Transport: TransportLAN,
		}},
	}

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled: true,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			t.Fatal("direct route unexpectedly dialed")
			return nil, nil
		},
	}

	_, err := forwarder.Forward(
		context.Background(),
		route,
		&testMeshLink{
			Conn:      routerSide,
			local:     "wd_b",
			remote:    "wd_a",
			transport: TransportLAN,
		},
	)
	if !errors.Is(err, ErrRouteNotOneHop) {
		t.Fatalf("Forward() error = %v, want ErrRouteNotOneHop", err)
	}
}

func TestForwarderRejectsOutgoingIdentityMismatch(t *testing.T) {
	t.Parallel()

	incomingConn, sourceSide := net.Pipe()
	outgoingConn, wrongPeerSide := net.Pipe()

	defer sourceSide.Close()
	defer wrongPeerSide.Close()

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			return &testMeshLink{
				Conn:      outgoingConn,
				local:     "wd_b",
				remote:    "wd_wrong",
				transport: TransportInternet,
			}, nil
		},
	}

	_, err := forwarder.Forward(
		context.Background(),
		oneHopTestRoute(time.Now().Add(time.Minute)),
		&testMeshLink{
			Conn:      incomingConn,
			local:     "wd_b",
			remote:    "wd_a",
			transport: TransportLAN,
		},
	)
	if !errors.Is(err, ErrLinkIdentityMismatch) {
		t.Fatalf("Forward() error = %v, want ErrLinkIdentityMismatch", err)
	}
}

func TestForwarderLANOnlyRejectsInternetHop(t *testing.T) {
	t.Parallel()

	routerSide, peerSide := net.Pipe()
	defer routerSide.Close()
	defer peerSide.Close()

	var authorized atomic.Bool

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
			LANOnly:            true,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			authorized.Store(true)
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			t.Fatal("disallowed route unexpectedly dialed")
			return nil, nil
		},
	}

	_, err := forwarder.Forward(
		context.Background(),
		oneHopTestRoute(time.Now().Add(time.Minute)),
		&testMeshLink{
			Conn:      routerSide,
			local:     "wd_b",
			remote:    "wd_a",
			transport: TransportLAN,
		},
	)
	if !errors.Is(err, ErrRouteNotAllowed) {
		t.Fatalf("Forward() error = %v, want ErrRouteNotAllowed", err)
	}
	if authorized.Load() {
		t.Fatal("policy-rejected route invoked authorizer")
	}
}

// Compile-time assertion for the test adapter.
var _ ForwardAuthorizer = forwardAuthorizerFunc(nil)

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

func TestServeRouteOpenAcceptsOnlyAfterAuthorizationAndDestinationDial(t *testing.T) {
	t.Parallel()

	clientSide, routerIncomingConn := net.Pipe()
	routerOutgoingConn, targetSide := net.Pipe()

	defer clientSide.Close()
	defer targetSide.Close()

	_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	_ = targetSide.SetDeadline(time.Now().Add(5 * time.Second))

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
	var dialed atomic.Bool

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
			MaxSessions:        1,
		},
		Authorizer: forwardAuthorizerFunc(func(_ context.Context, req ForwardRequest) error {
			if req.Router != "wd_b" ||
				req.Route.Source != "wd_a" ||
				req.Route.Destination != "wd_c" {
				t.Errorf("unexpected authorization request: %+v", req)
			}

			authorized.Store(true)
			return nil
		}),
		DialNext: func(_ context.Context, hop RouteHop) (Link, error) {
			if !authorized.Load() {
				t.Error("destination dial happened before authorization")
			}
			if hop.From != "wd_b" || hop.To != "wd_c" {
				t.Errorf("unexpected outgoing hop: %+v", hop)
			}

			dialed.Store(true)
			return outgoing, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type response struct {
		result ForwardResult
		err    error
	}

	done := make(chan response, 1)
	go func() {
		result, err := forwarder.ServeRouteOpen(ctx, incoming)
		done <- response{result: result, err: err}
	}()

	route := oneHopTestRoute(time.Now().Add(time.Minute))

	if err := WriteRouteOpenRequest(clientSide, RouteOpenRequest{
		Route: route,
	}); err != nil {
		t.Fatalf("WriteRouteOpenRequest() error: %v", err)
	}

	openResp, err := ReadRouteOpenResponse(clientSide)
	if err != nil {
		t.Fatalf("ReadRouteOpenResponse() error: %v", err)
	}
	if !openResp.Accepted || openResp.Code != "" {
		t.Fatalf("route-open response = %+v, want accepted", openResp)
	}
	if !authorized.Load() {
		t.Fatal("router accepted before authorization")
	}
	if !dialed.Load() {
		t.Fatal("router accepted before destination dial")
	}

	const request = "opaque-inner-tls-request"
	const reply = "opaque-inner-tls-response"

	targetDone := make(chan error, 1)
	go func() {
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(targetSide, buf); err != nil {
			targetDone <- err
			return
		}
		if string(buf) != request {
			targetDone <- errors.New("target received altered tunnel bytes")
			return
		}

		if _, err := targetSide.Write([]byte(reply)); err != nil {
			targetDone <- err
			return
		}

		targetDone <- nil
	}()

	if _, err := clientSide.Write([]byte(request)); err != nil {
		t.Fatalf("write opaque tunnel request: %v", err)
	}

	buf := make([]byte, len(reply))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("read opaque tunnel response: %v", err)
	}
	if string(buf) != reply {
		t.Fatalf("opaque response = %q, want %q", buf, reply)
	}

	if err := <-targetDone; err != nil {
		t.Fatalf("target tunnel exchange: %v", err)
	}

	_ = clientSide.Close()

	got := <-done
	if got.err != nil {
		t.Fatalf("ServeRouteOpen() error: %v", got.err)
	}
	if got.result.BytesToDestination != int64(len(request)) {
		t.Fatalf(
			"BytesToDestination = %d, want %d",
			got.result.BytesToDestination,
			len(request),
		)
	}
	if got.result.BytesToSource != int64(len(reply)) {
		t.Fatalf(
			"BytesToSource = %d, want %d",
			got.result.BytesToSource,
			len(reply),
		)
	}
}

func TestServeRouteOpenDeniesBeforeDialWithGenericResponse(t *testing.T) {
	t.Parallel()

	clientSide, routerSide := net.Pipe()
	defer clientSide.Close()

	_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))

	var dialed atomic.Bool

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			// Deliberately detailed local failure. It must never appear in the
			// route-control response.
			return errors.New("authorization backend rejected private detail")
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			dialed.Store(true)
			return nil, nil
		},
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := forwarder.ServeRouteOpen(
			context.Background(),
			&testMeshLink{
				Conn:      routerSide,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		errCh <- err
	}()

	if err := WriteRouteOpenRequest(clientSide, RouteOpenRequest{
		Route: oneHopTestRoute(time.Now().Add(time.Minute)),
	}); err != nil {
		t.Fatalf("WriteRouteOpenRequest() error: %v", err)
	}

	resp, err := ReadRouteOpenResponse(clientSide)
	if err != nil {
		t.Fatalf("ReadRouteOpenResponse() error: %v", err)
	}
	if resp.Accepted || resp.Code != RouteOpenCodeDenied {
		t.Fatalf("route-open response = %+v, want generic denial", resp)
	}
	if dialed.Load() {
		t.Fatal("unauthorized route dialed destination")
	}

	if err := <-errCh; !errors.Is(err, ErrForwardDenied) {
		t.Fatalf("ServeRouteOpen() error = %v, want ErrForwardDenied", err)
	}
}

func TestServeRouteOpenInvalidRouteDoesNotAuthorizeOrDial(t *testing.T) {
	t.Parallel()

	clientSide, routerSide := net.Pipe()
	defer clientSide.Close()

	_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))

	var authorized atomic.Bool
	var dialed atomic.Bool

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled: true,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			authorized.Store(true)
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			dialed.Store(true)
			return nil, nil
		},
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := forwarder.ServeRouteOpen(
			context.Background(),
			&testMeshLink{
				Conn:      routerSide,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		errCh <- err
	}()

	direct := Route{
		ID:          "not-one-hop",
		Source:      "wd_a",
		Destination: "wd_b",
		ExpiresAt:   time.Now().Add(time.Minute),
		Hops: []RouteHop{{
			From:      "wd_a",
			To:        "wd_b",
			Transport: TransportLAN,
		}},
	}

	if err := WriteRouteOpenRequest(clientSide, RouteOpenRequest{
		Route: direct,
	}); err != nil {
		t.Fatalf("WriteRouteOpenRequest() error: %v", err)
	}

	resp, err := ReadRouteOpenResponse(clientSide)
	if err != nil {
		t.Fatalf("ReadRouteOpenResponse() error: %v", err)
	}
	if resp.Accepted || resp.Code != RouteOpenCodeInvalidRequest {
		t.Fatalf("route-open response = %+v, want invalid_request", resp)
	}
	if authorized.Load() {
		t.Fatal("invalid route invoked authorizer")
	}
	if dialed.Load() {
		t.Fatal("invalid route dialed destination")
	}

	if err := <-errCh; !errors.Is(err, ErrRouteNotOneHop) {
		t.Fatalf("ServeRouteOpen() error = %v, want ErrRouteNotOneHop", err)
	}
}

func TestServeRouteOpenContextCancellationInterruptsControlRead(t *testing.T) {
	t.Parallel()

	clientSide, routerSide := net.Pipe()
	defer clientSide.Close()

	ctx, cancel := context.WithCancel(context.Background())

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled: true,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := forwarder.ServeRouteOpen(
			ctx,
			&testMeshLink{
				Conn:      routerSide,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		errCh <- err
	}()

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ServeRouteOpen() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeRouteOpen did not stop after context cancellation")
	}
}

func activeForwardSessions(f *Forwarder) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active
}

func TestForwarderReleasesSessionAfterAuthorizationDenial(t *testing.T) {
	t.Parallel()

	routerSide, peerSide := net.Pipe()
	defer peerSide.Close()

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:     true,
			MaxSessions: 1,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			return errors.New("denied")
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			t.Fatal("authorization-denied route unexpectedly dialed")
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
	if got := activeForwardSessions(forwarder); got != 0 {
		t.Fatalf("active sessions = %d after denial, want 0", got)
	}
}

func TestForwarderReleasesSessionAfterDialFailure(t *testing.T) {
	t.Parallel()

	routerSide, peerSide := net.Pipe()
	defer peerSide.Close()

	dialErr := errors.New("destination unavailable")

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:     true,
			MaxSessions: 1,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			return nil, dialErr
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
	if !errors.Is(err, dialErr) {
		t.Fatalf("Forward() error = %v, want wrapped dial failure", err)
	}
	if got := activeForwardSessions(forwarder); got != 0 {
		t.Fatalf("active sessions = %d after dial failure, want 0", got)
	}
}

func TestForwarderReleasesSessionAfterNormalDisconnect(t *testing.T) {
	t.Parallel()

	clientSide, routerIncoming := net.Pipe()
	routerOutgoing, targetSide := net.Pipe()

	defer targetSide.Close()

	dialed := make(chan struct{})

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:     true,
			MaxSessions: 1,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			close(dialed)
			return &testMeshLink{
				Conn:      routerOutgoing,
				local:     "wd_b",
				remote:    "wd_c",
				transport: TransportInternet,
			}, nil
		},
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := forwarder.Forward(
			context.Background(),
			oneHopTestRoute(time.Now().Add(time.Minute)),
			&testMeshLink{
				Conn:      routerIncoming,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		errCh <- err
	}()

	select {
	case <-dialed:
	case <-time.After(2 * time.Second):
		t.Fatal("destination was not dialed")
	}

	if got := activeForwardSessions(forwarder); got != 1 {
		t.Fatalf("active sessions = %d while forwarding, want 1", got)
	}

	_ = clientSide.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Forward() error after normal disconnect: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Forward() did not stop after disconnect")
	}

	if got := activeForwardSessions(forwarder); got != 0 {
		t.Fatalf("active sessions = %d after disconnect, want 0", got)
	}
}

func TestServeRouteOpenReleasesSessionWhenAcceptanceWriteFails(t *testing.T) {
	t.Parallel()

	clientSide, routerIncoming := net.Pipe()
	routerOutgoing, targetSide := net.Pipe()

	defer targetSide.Close()

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:     true,
			MaxSessions: 1,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			return &testMeshLink{
				Conn:      routerOutgoing,
				local:     "wd_b",
				remote:    "wd_c",
				transport: TransportInternet,
			}, nil
		},
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := forwarder.ServeRouteOpen(
			context.Background(),
			&testMeshLink{
				Conn:      routerIncoming,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		errCh <- err
	}()

	if err := WriteRouteOpenRequest(clientSide, RouteOpenRequest{
		Route: oneHopTestRoute(time.Now().Add(time.Minute)),
	}); err != nil {
		t.Fatalf("WriteRouteOpenRequest() error: %v", err)
	}

	// Do not read the acceptance. Closing A forces B's control write to fail.
	_ = clientSide.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ServeRouteOpen unexpectedly succeeded after acceptance write failure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeRouteOpen did not stop after peer close")
	}

	if got := activeForwardSessions(forwarder); got != 0 {
		t.Fatalf("active sessions = %d after acceptance failure, want 0", got)
	}

	_ = targetSide.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := targetSide.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("destination link read error = %v, want EOF", err)
	}
}

func TestServeRouteOpenEnforcesMaxSessionsAndReleasesOnCancellation(t *testing.T) {
	t.Parallel()

	clientOne, routerOne := net.Pipe()
	routerOutgoing, targetSide := net.Pipe()

	defer clientOne.Close()
	defer targetSide.Close()

	ctxOne, cancelOne := context.WithCancel(context.Background())
	defer cancelOne()

	var dialCount atomic.Int32

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy: RouterPolicy{
			Enabled:     true,
			MaxSessions: 1,
		},
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			if dialCount.Add(1) != 1 {
				t.Fatal("second route unexpectedly reached destination dial")
			}
			return &testMeshLink{
				Conn:      routerOutgoing,
				local:     "wd_b",
				remote:    "wd_c",
				transport: TransportInternet,
			}, nil
		},
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := forwarder.ServeRouteOpen(
			ctxOne,
			&testMeshLink{
				Conn:      routerOne,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		firstDone <- err
	}()

	route := oneHopTestRoute(time.Now().Add(time.Minute))

	if err := WriteRouteOpenRequest(clientOne, RouteOpenRequest{Route: route}); err != nil {
		t.Fatalf("first WriteRouteOpenRequest() error: %v", err)
	}

	firstResp, err := ReadRouteOpenResponse(clientOne)
	if err != nil {
		t.Fatalf("first ReadRouteOpenResponse() error: %v", err)
	}
	if !firstResp.Accepted {
		t.Fatalf("first route was not accepted: %+v", firstResp)
	}

	if got := activeForwardSessions(forwarder); got != 1 {
		t.Fatalf("active sessions = %d after first acceptance, want 1", got)
	}

	clientTwo, routerTwo := net.Pipe()
	defer clientTwo.Close()

	secondDone := make(chan error, 1)
	go func() {
		_, err := forwarder.ServeRouteOpen(
			context.Background(),
			&testMeshLink{
				Conn:      routerTwo,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		secondDone <- err
	}()

	if err := WriteRouteOpenRequest(clientTwo, RouteOpenRequest{Route: route}); err != nil {
		t.Fatalf("second WriteRouteOpenRequest() error: %v", err)
	}

	secondResp, err := ReadRouteOpenResponse(clientTwo)
	if err != nil {
		t.Fatalf("second ReadRouteOpenResponse() error: %v", err)
	}
	if secondResp.Accepted || secondResp.Code != RouteOpenCodeBusy {
		t.Fatalf("second route response = %+v, want router_busy", secondResp)
	}

	if err := <-secondDone; !errors.Is(err, ErrRouterBusy) {
		t.Fatalf("second ServeRouteOpen() error = %v, want ErrRouterBusy", err)
	}

	if got := dialCount.Load(); got != 1 {
		t.Fatalf("destination dial count = %d, want 1", got)
	}

	cancelOne()

	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first ServeRouteOpen() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first route did not stop after cancellation")
	}

	if got := activeForwardSessions(forwarder); got != 0 {
		t.Fatalf("active sessions = %d after cancellation, want 0", got)
	}
}

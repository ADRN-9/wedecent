package mesh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const routeControlIOTimeout = 15 * time.Second

var (
	ErrRoutingDisabled              = errors.New("mesh: routing is disabled")
	ErrForwardAuthorizationRequired = errors.New("mesh: forwarding authorization is required")
	ErrForwardDenied                = errors.New("mesh: forwarding denied")
	ErrForwardDialerRequired        = errors.New("mesh: forwarding dialer is required")
	ErrInvalidRoute                 = errors.New("mesh: invalid route")
	ErrRouteNotOneHop               = errors.New("mesh: route is not a one-hop routed path")
	ErrRouterMismatch               = errors.New("mesh: route does not traverse this router")
	ErrLinkIdentityMismatch         = errors.New("mesh: authenticated link identity does not match route")
	ErrRouteNotAllowed              = errors.New("mesh: route is not allowed by router policy")
	ErrRouterBusy                   = errors.New("mesh: router session limit reached")
)

// ForwardRequest is the authorization context for one routed session.
//
// Authorization is intentionally independent from structural route validation.
// Implementations are expected to enforce trust, organization and account policy.
type ForwardRequest struct {
	Router        DeviceID
	Route         Route
	Authorization RouteAuthorization
	Policy        RouterPolicy
}

// ForwardAuthorizer decides whether a structurally valid route may be forwarded.
type ForwardAuthorizer interface {
	AuthorizeForward(context.Context, ForwardRequest) error
}

// ForwardDialFunc opens an authenticated mesh link for the router's outgoing hop.
type ForwardDialFunc func(context.Context, RouteHop) (Link, error)

// ForwardResult contains opaque byte accounting only.
//
// It intentionally contains no terminal/session payload.
type ForwardResult struct {
	BytesToDestination int64
	BytesToSource      int64
}

// Forwarder forwards an authorized A -> B -> C route.
//
// Policy may be changed after construction only through SetPolicy. Each new
// routed operation snapshots one policy value and uses it for its full setup;
// active tunnels are not retroactively re-authorized when policy changes.
// Other configuration must not be mutated while Forward or ServeRouteOpen is
// running. Incoming and outgoing links are owned for the duration of the routed
// operation and are closed when it ends.
type Forwarder struct {
	LocalID    DeviceID
	Policy     RouterPolicy
	Authorizer ForwardAuthorizer
	DialNext   ForwardDialFunc

	// Now exists for deterministic validation tests. Production callers should
	// leave it nil so UTC wall-clock time is used.
	Now func() time.Time

	mu                sync.Mutex
	active            int
	bytesForwarded    uint64
	sessionsForwarded uint64
}

type preparedForward struct {
	ctx      context.Context
	cancel   context.CancelFunc
	outgoing Link
	release  func()
}

// Forward validates and authorizes an exact A -> B -> C route, then copies
// opaque protected bytes between the authenticated neighboring links.
func (f *Forwarder) Forward(ctx context.Context, route Route, incoming Link) (ForwardResult, error) {
	if incoming == nil {
		return ForwardResult{}, ErrLinkIdentityMismatch
	}
	defer incoming.Close()

	prepared, err := f.prepareForward(
		ctx,
		route,
		RouteAuthorization{},
		incoming,
	)
	if err != nil {
		return ForwardResult{}, err
	}
	defer prepared.close()

	f.beginForwarding()
	result, err := copyOpaque(prepared.ctx, incoming, prepared.outgoing)
	f.recordForwardResult(result)
	return result, err
}

// ServeRouteOpen handles the outer A -> B route-control handshake.
//
// The incoming link must already authenticate A as its remote peer. The method
// consumes exactly one route-open request. It sends Accepted only after route
// validation, authorization, capacity acquisition, destination dialing, and
// authenticated B -> C link verification have all succeeded.
//
// After Accepted, no route-control or terminal frames are parsed by B. The same
// incoming link becomes an opaque byte tunnel for the inner A <-> C protected
// session.
func (f *Forwarder) ServeRouteOpen(ctx context.Context, incoming Link) (ForwardResult, error) {
	if incoming == nil {
		return ForwardResult{}, ErrLinkIdentityMismatch
	}
	defer incoming.Close()

	req, err := readRouteOpenRequestWithContext(ctx, incoming)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ForwardResult{}, ctxErr
		}

		// The peer receives only a stable non-sensitive result code. Parser
		// details remain local.
		_ = writeRouteOpenResponseWithContext(ctx, incoming, RouteOpenResponse{
			Accepted: false,
			Code:     RouteOpenCodeInvalidRequest,
		})
		return ForwardResult{}, err
	}

	prepared, err := f.prepareForward(
		ctx,
		req.Route,
		req.Authorization,
		incoming,
	)
	if err != nil {
		code := routeOpenCodeForForwardError(err)

		if writeErr := writeRouteOpenResponseWithContext(ctx, incoming, RouteOpenResponse{
			Accepted: false,
			Code:     code,
		}); writeErr != nil {
			return ForwardResult{}, errors.Join(
				err,
				fmt.Errorf("mesh: write route-open rejection: %w", writeErr),
			)
		}

		return ForwardResult{}, err
	}
	defer prepared.close()

	// Acceptance is part of the route setup itself. If the route expires while
	// the peer is not reading the response, close the link rather than letting
	// a stale route remain stuck in the control phase.
	if err := writeRouteOpenResponseWithContext(
		prepared.ctx,
		incoming,
		RouteOpenResponse{Accepted: true},
	); err != nil {
		return ForwardResult{}, fmt.Errorf("mesh: write route-open acceptance: %w", err)
	}

	f.beginForwarding()
	result, err := copyOpaque(prepared.ctx, incoming, prepared.outgoing)
	f.recordForwardResult(result)
	return result, err
}

func readRouteOpenRequestWithContext(
	ctx context.Context,
	incoming Link,
) (RouteOpenRequest, error) {
	readCtx, cancel := context.WithTimeout(ctx, routeControlIOTimeout)
	defer cancel()

	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(readCtx, func() {
		defer close(closeDone)
		_ = incoming.Close()
	})

	req, err := ReadRouteOpenRequest(incoming)

	// If cancellation already started the close callback, wait for it to finish
	// before inspecting the context or returning. This prevents a successful
	// control read racing with a late callback that closes the tunnel afterward.
	if !stopClose() {
		<-closeDone
	}

	if ctxErr := readCtx.Err(); ctxErr != nil {
		return RouteOpenRequest{}, ctxErr
	}
	return req, err
}

func writeRouteOpenResponseWithContext(
	ctx context.Context,
	link Link,
	resp RouteOpenResponse,
) error {
	writeCtx, cancel := context.WithTimeout(ctx, routeControlIOTimeout)
	defer cancel()

	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(writeCtx, func() {
		defer close(closeDone)
		_ = link.Close()
	})

	err := WriteRouteOpenResponse(link, resp)

	// As with the read path, do not return while a context-triggered close is
	// still running against the same authenticated link.
	if !stopClose() {
		<-closeDone
	}

	if ctxErr := writeCtx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

func (f *Forwarder) prepareForward(
	ctx context.Context,
	route Route,
	authorization RouteAuthorization,
	incoming Link,
) (*preparedForward, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(f.LocalID)) == "" {
		return nil, errors.New("mesh: router device ID is required")
	}

	policy := f.policySnapshot()
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if !policy.Enabled {
		return nil, ErrRoutingDisabled
	}
	if f.Authorizer == nil {
		return nil, ErrForwardAuthorizationRequired
	}
	if f.DialNext == nil {
		return nil, ErrForwardDialerRequired
	}
	if incoming == nil {
		return nil, ErrLinkIdentityMismatch
	}

	now := time.Now().UTC()
	if f.Now != nil {
		now = f.Now()
	}

	if err := route.Validate(now); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRoute, err)
	}
	if len(route.Hops) != 2 {
		return nil, ErrRouteNotOneHop
	}

	first := route.Hops[0]
	second := route.Hops[1]

	if first.To != f.LocalID || second.From != f.LocalID {
		return nil, ErrRouterMismatch
	}

	if incoming.Local() != f.LocalID ||
		incoming.Remote() != route.Source ||
		incoming.Transport() != first.Transport {
		return nil, ErrLinkIdentityMismatch
	}

	if policy.LANOnly &&
		(first.Transport != TransportLAN || second.Transport != TransportLAN) {
		return nil, ErrRouteNotAllowed
	}

	if !f.acquireSession(policy.MaxSessions) {
		return nil, ErrRouterBusy
	}

	routeCtx, cancel := context.WithDeadline(ctx, route.ExpiresAt)

	release := func() {
		cancel()
		f.releaseSession()
	}

	authRoute := cloneAuthorizationRoute(route)
	authAuthorization := cloneRouteAuthorization(authorization)

	if err := f.Authorizer.AuthorizeForward(routeCtx, ForwardRequest{
		Router:        f.LocalID,
		Route:         authRoute,
		Authorization: authAuthorization,
		Policy:        policy,
	}); err != nil {
		ctxErr := routeCtx.Err()
		release()

		if ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrForwardDenied
	}

	if err := routeCtx.Err(); err != nil {
		release()
		return nil, err
	}

	outgoing, err := f.DialNext(routeCtx, second)
	if err != nil {
		ctxErr := routeCtx.Err()
		release()

		if ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("mesh: dial routed destination: %w", err)
	}

	if outgoing == nil {
		release()
		return nil, ErrLinkIdentityMismatch
	}

	if outgoing.Local() != f.LocalID ||
		outgoing.Remote() != route.Destination ||
		outgoing.Transport() != second.Transport {
		_ = outgoing.Close()
		release()
		return nil, ErrLinkIdentityMismatch
	}

	if err := routeCtx.Err(); err != nil {
		_ = outgoing.Close()
		release()
		return nil, err
	}

	return &preparedForward{
		ctx:      routeCtx,
		cancel:   cancel,
		outgoing: outgoing,
		release:  f.releaseSession,
	}, nil
}

func (p *preparedForward) close() {
	p.cancel()
	_ = p.outgoing.Close()
	p.release()
}

func routeOpenCodeForForwardError(err error) RouteOpenCode {
	switch {
	case errors.Is(err, ErrRouterBusy):
		return RouteOpenCodeBusy

	case errors.Is(err, ErrInvalidRoute),
		errors.Is(err, ErrRouteNotOneHop),
		errors.Is(err, ErrRouterMismatch):
		return RouteOpenCodeInvalidRequest

	case errors.Is(err, ErrRoutingDisabled),
		errors.Is(err, ErrForwardDenied),
		errors.Is(err, ErrRouteNotAllowed),
		errors.Is(err, ErrLinkIdentityMismatch):
		return RouteOpenCodeDenied

	default:
		// Configuration failures, expiry/cancellation, and destination dialing
		// failures intentionally collapse to a generic availability result.
		return RouteOpenCodeUnavailable
	}
}

func (f *Forwarder) acquireSession(maxSessions int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if maxSessions > 0 && f.active >= maxSessions {
		return false
	}

	f.active++
	return true
}

func (f *Forwarder) releaseSession() {
	f.mu.Lock()
	f.active--
	f.mu.Unlock()
}

func (f *Forwarder) beginForwarding() {
	f.mu.Lock()
	if f.sessionsForwarded != ^uint64(0) {
		f.sessionsForwarded++
	}
	f.mu.Unlock()
}

func (f *Forwarder) recordForwardResult(result ForwardResult) {
	var bytes uint64
	if result.BytesToDestination > 0 {
		bytes = uint64(result.BytesToDestination)
	}
	if result.BytesToSource > 0 {
		bytes = saturatingAddUint64(bytes, uint64(result.BytesToSource))
	}

	f.mu.Lock()
	f.bytesForwarded = saturatingAddUint64(f.bytesForwarded, bytes)
	f.mu.Unlock()
}

func saturatingAddUint64(left, right uint64) uint64 {
	const maxUint64 = ^uint64(0)
	if maxUint64-left < right {
		return maxUint64
	}
	return left + right
}

type copyOutcome struct {
	toDestination bool
	bytes         int64
	err           error
}

func copyOpaque(ctx context.Context, incoming, outgoing Link) (ForwardResult, error) {
	results := make(chan copyOutcome, 2)

	go func() {
		n, err := io.Copy(outgoing, incoming)
		results <- copyOutcome{
			toDestination: true,
			bytes:         n,
			err:           err,
		}
	}()

	go func() {
		n, err := io.Copy(incoming, outgoing)
		results <- copyOutcome{
			toDestination: false,
			bytes:         n,
			err:           err,
		}
	}()

	var (
		result    ForwardResult
		firstErr  error
		closeOnce sync.Once
	)

	closeLinks := func() {
		closeOnce.Do(func() {
			_ = incoming.Close()
			_ = outgoing.Close()
		})
	}
	defer closeLinks()

	ctxDone := ctx.Done()
	completed := 0

	for completed < 2 {
		select {
		case outcome := <-results:
			completed++

			if outcome.toDestination {
				result.BytesToDestination += outcome.bytes
			} else {
				result.BytesToSource += outcome.bytes
			}

			if firstErr == nil && !benignCopyError(outcome.err) {
				firstErr = outcome.err
			}

			// A routed WeDecent session treats either direction ending as a
			// disconnect. Close both links so the other copy cannot leak.
			if completed == 1 {
				closeLinks()
			}

		case <-ctxDone:
			closeLinks()
			ctxDone = nil
		}
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}
	if firstErr != nil {
		return result, fmt.Errorf("mesh: forwarding stream: %w", firstErr)
	}

	return result, nil
}

func benignCopyError(err error) bool {
	return err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed)
}

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

var (
	ErrRoutingDisabled              = errors.New("mesh: routing is disabled")
	ErrForwardAuthorizationRequired = errors.New("mesh: forwarding authorization is required")
	ErrForwardDenied                = errors.New("mesh: forwarding denied")
	ErrForwardDialerRequired        = errors.New("mesh: forwarding dialer is required")
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
	Router DeviceID
	Route  Route
	Policy RouterPolicy
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
// Policy and configuration must not be mutated while Forward is running.
// The incoming and outgoing Links are owned by Forward for the duration of
// the routed session and are closed when forwarding ends.
type Forwarder struct {
	LocalID    DeviceID
	Policy     RouterPolicy
	Authorizer ForwardAuthorizer
	DialNext   ForwardDialFunc

	// Now exists for deterministic validation tests. Production callers should
	// leave it nil so UTC wall-clock time is used.
	Now func() time.Time

	mu     sync.Mutex
	active int
}

// Forward validates and authorizes an exact A -> B -> C route, then copies
// opaque protected bytes between the authenticated neighboring links.
func (f *Forwarder) Forward(ctx context.Context, route Route, incoming Link) (ForwardResult, error) {
	if incoming == nil {
		return ForwardResult{}, ErrLinkIdentityMismatch
	}
	defer incoming.Close()

	if err := ctx.Err(); err != nil {
		return ForwardResult{}, err
	}
	if strings.TrimSpace(string(f.LocalID)) == "" {
		return ForwardResult{}, errors.New("mesh: router device ID is required")
	}
	if err := f.Policy.Validate(); err != nil {
		return ForwardResult{}, err
	}
	if !f.Policy.Enabled {
		return ForwardResult{}, ErrRoutingDisabled
	}
	if f.Authorizer == nil {
		return ForwardResult{}, ErrForwardAuthorizationRequired
	}
	if f.DialNext == nil {
		return ForwardResult{}, ErrForwardDialerRequired
	}
	now := time.Now().UTC()
	if f.Now != nil {
		now = f.Now()
	}
	if err := route.Validate(now); err != nil {
		return ForwardResult{}, err
	}
	if len(route.Hops) != 2 {
		return ForwardResult{}, ErrRouteNotOneHop
	}

	first := route.Hops[0]
	second := route.Hops[1]

	if first.To != f.LocalID || second.From != f.LocalID {
		return ForwardResult{}, ErrRouterMismatch
	}
	if incoming.Local() != f.LocalID ||
		incoming.Remote() != route.Source ||
		incoming.Transport() != first.Transport {
		return ForwardResult{}, ErrLinkIdentityMismatch
	}
	if f.Policy.LANOnly &&
		(first.Transport != TransportLAN || second.Transport != TransportLAN) {
		return ForwardResult{}, ErrRouteNotAllowed
	}

	if !f.acquireSession() {
		return ForwardResult{}, ErrRouterBusy
	}
	defer f.releaseSession()

	routeCtx, cancel := context.WithDeadline(ctx, route.ExpiresAt)
	defer cancel()

	authRoute := route
	authRoute.Hops = append([]RouteHop(nil), route.Hops...)
	if err := f.Authorizer.AuthorizeForward(routeCtx, ForwardRequest{
		Router: f.LocalID,
		Route:  authRoute,
		Policy: f.Policy,
	}); err != nil {
		return ForwardResult{}, ErrForwardDenied
	}

	outgoing, err := f.DialNext(routeCtx, second)
	if err != nil {
		return ForwardResult{}, fmt.Errorf("mesh: dial routed destination: %w", err)
	}
	if outgoing == nil {
		return ForwardResult{}, ErrLinkIdentityMismatch
	}
	defer outgoing.Close()

	if outgoing.Local() != f.LocalID ||
		outgoing.Remote() != route.Destination ||
		outgoing.Transport() != second.Transport {
		return ForwardResult{}, ErrLinkIdentityMismatch
	}

	return copyOpaque(routeCtx, incoming, outgoing)
}

func (f *Forwarder) acquireSession() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.Policy.MaxSessions > 0 && f.active >= f.Policy.MaxSessions {
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

type copyOutcome struct {
	toDestination bool
	bytes         int64
	err           error
}

func copyOpaque(ctx context.Context, incoming, outgoing Link) (ForwardResult, error) {
	results := make(chan copyOutcome, 2)

	go func() {
		n, err := io.Copy(outgoing, incoming)
		results <- copyOutcome{toDestination: true, bytes: n, err: err}
	}()
	go func() {
		n, err := io.Copy(incoming, outgoing)
		results <- copyOutcome{toDestination: false, bytes: n, err: err}
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

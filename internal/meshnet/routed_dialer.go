package meshnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/transport"
)

const routeOpenTimeout = 15 * time.Second

var (
	ErrRoutedDialerConfig = errors.New("meshnet: invalid routed-dialer configuration")
	ErrRoutedRouteInvalid = errors.New("meshnet: invalid routed connection route")
	ErrRoutedPeerMismatch = errors.New("meshnet: resolved router does not match route")
	ErrRouteRejected      = errors.New("meshnet: routed connection rejected")
)

// PeerResolver resolves router-owned trusted neighbor information.
//
// The route request supplies only cryptographic device IDs and transports.
// Network locators come from the resolver, never from the session endpoint
// argument or route-control peer.
type PeerResolver interface {
	Resolve(
		context.Context,
		mesh.DeviceID,
		mesh.TransportName,
	) (ResolvedPeer, error)
}

// RouteRejectedError exposes only the stable, non-sensitive rejection code
// defined by the mesh route-control protocol.
type RouteRejectedError struct {
	Code mesh.RouteOpenCode
}

func (e *RouteRejectedError) Error() string {
	return fmt.Sprintf("%s: %s", ErrRouteRejected, e.Code)
}

func (e *RouteRejectedError) Unwrap() error {
	return ErrRouteRejected
}

// RoutedDialer establishes an authenticated outer connection to the first-hop
// router, opens one exact two-hop route, and returns the accepted tunnel.
//
// The endpoint argument passed to Dial is intentionally ignored. In normal
// session.Client use it is C's endpoint locator, but allowing it to influence
// the A->B connection would turn routing into an arbitrary network proxy.
//
// After Dial succeeds, session.Client wraps the returned transport.Conn in its
// existing endpoint-pinned A<->C TLS connection.
type RoutedDialer struct {
	Identity *identity.Identity
	Resolver PeerResolver
	Route    mesh.Route

	// DialTCP exists for deterministic tests. Production callers normally leave
	// it nil and use the standard direct TCP dial below.
	DialTCP func(context.Context, string) (net.Conn, error)

	Now func() time.Time
}

func (d RoutedDialer) Dial(
	ctx context.Context,
	_ string,
) (transport.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.Identity == nil || d.Resolver == nil {
		return nil, ErrRoutedDialerConfig
	}

	route := d.Route
	route.Hops = append([]mesh.RouteHop(nil), d.Route.Hops...)

	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}

	if err := route.Validate(now); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoutedRouteInvalid, err)
	}
	if len(route.Hops) != 2 {
		return nil, fmt.Errorf(
			"%w: one-hop routed dialing requires exactly two route hops",
			ErrRoutedRouteInvalid,
		)
	}

	localID := mesh.DeviceID(strings.TrimSpace(d.Identity.ID))
	if localID == "" ||
		route.Source != localID ||
		route.Hops[0].From != localID {
		return nil, fmt.Errorf(
			"%w: route source does not match local identity",
			ErrRoutedRouteInvalid,
		)
	}

	routerID := route.Hops[0].To
	routerTransport := route.Hops[0].Transport

	peer, err := d.Resolver.Resolve(
		ctx,
		routerID,
		routerTransport,
	)
	if err != nil {
		return nil, err
	}

	if peer.ID != routerID || peer.Transport != routerTransport {
		return nil, ErrRoutedPeerMismatch
	}

	address, err := routedTCPAddress(peer.Locator)
	if err != nil {
		return nil, err
	}

	dialTCP := d.DialTCP
	if dialTCP == nil {
		dialTCP = defaultRoutedTCPDial
	}

	raw, err := dialTCP(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("meshnet: dial trusted router: %w", err)
	}

	link, err := DialTrustedLink(
		ctx,
		raw,
		d.Identity,
		peer,
	)
	if err != nil {
		// DialTrustedLink owns and closes raw on failure.
		return nil, err
	}

	if err := openRoutedTunnel(ctx, link, route); err != nil {
		_ = link.Close()
		return nil, err
	}

	return link, nil
}

func openRoutedTunnel(
	ctx context.Context,
	link *TLSLink,
	route mesh.Route,
) error {
	if link == nil {
		return ErrRoutedDialerConfig
	}

	deadline := time.Now().Add(routeOpenTimeout)
	if route.ExpiresAt.Before(deadline) {
		deadline = route.ExpiresAt
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	controlCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	if err := link.SetDeadline(deadline); err != nil {
		return fmt.Errorf("meshnet: set route-open deadline: %w", err)
	}

	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(controlCtx, func() {
		defer close(closeDone)
		_ = link.Close()
	})

	err := mesh.WriteRouteOpenRequest(
		link,
		mesh.RouteOpenRequest{Route: route},
	)

	var response mesh.RouteOpenResponse
	if err == nil {
		response, err = mesh.ReadRouteOpenResponse(link)
	}

	if !stopClose() {
		<-closeDone
	}

	if ctxErr := controlCtx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("meshnet: route-open exchange: %w", err)
	}

	if !response.Accepted {
		return &RouteRejectedError{Code: response.Code}
	}

	if err := link.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("meshnet: clear route-open deadline: %w", err)
	}

	return nil
}

func routedTCPAddress(locator string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(locator))
	if err != nil ||
		u.Scheme != "tcp" ||
		u.Host == "" ||
		u.User != nil ||
		u.Path != "" ||
		u.RawQuery != "" ||
		u.Fragment != "" {
		return "", ErrRoutedDialerConfig
	}

	address, err := trustedHostPort(u.Host)
	if err != nil {
		return "", ErrRoutedDialerConfig
	}

	return address, nil
}

func defaultRoutedTCPDial(
	ctx context.Context,
	address string,
) (net.Conn, error) {
	nd := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := nd.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	return conn, nil
}

var _ transport.Dialer = RoutedDialer{}

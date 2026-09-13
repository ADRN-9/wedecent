package meshruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/meshstate"
	"wedecent.com/wedecent/internal/trust"
)

const RouteAuthorizationReplayFile = "route-authorization-replay.json"

var (
	ErrConfig = errors.New(
		"meshruntime: invalid production routing configuration",
	)

	ErrUnsupportedPolicy = errors.New(
		"meshruntime: unsupported production routing policy",
	)

	ErrUnsupportedTransport = errors.New(
		"meshruntime: unsupported production routing transport",
	)
)

// Config contains only construction-time routing state.
//
// Open does not bind sockets and does not enable any production listener.
// The caller remains responsible for deciding whether and where routing roles
// are exposed.
type Config struct {
	StateDir string
	Identity *identity.Identity

	// EndpointHandler is C's existing endpoint-session server. meshnet only
	// sees its narrow ServeConn(net.Conn) interface.
	EndpointHandler meshnet.EndpointConnHandler

	// RouterPolicy controls B's forwarding behavior. Stage 3 deliberately
	// supports explicit trusted-device routing only. Public and other policy
	// models remain fail-closed until implemented separately.
	RouterPolicy mesh.RouterPolicy

	// DestinationTransport is the authenticated B -> C outer transport for
	// this destination ingress instance.
	DestinationTransport mesh.TransportName

	// LANDiscoveryTimeout controls fingerprint-pinned signed discovery when
	// a trusted source/router/destination is reached using TransportLAN.
	// Zero safely makes LAN resolution unavailable.
	LANDiscoveryTimeout time.Duration
}

// Runtime is the non-listening production composition root for Stage 3
// one-hop routing.
//
// It owns no listeners and starts no goroutines. It only binds already-tested
// security primitives to the exact trust domains that each routing role needs.
type Runtime struct {
	Identity *identity.Identity

	Authority meshstate.RouteAuthorizationAuthority
	Replay    *meshstate.FileRouteAuthorizationReplay

	SourceRouters      *trust.Store
	RouterSources      *trust.Store
	RouterDestinations *trust.Store
	DestinationRouters *trust.Store

	SourceRouterResolver      *meshnet.TrustedPeerResolver
	RouterDestinationResolver *meshnet.TrustedPeerResolver

	Router      *mesh.Forwarder
	Destination meshnet.DestinationIngress
}

// Open constructs fail-closed Stage-3 routing components without opening any
// network listener.
//
// Order matters: the locally provisioned verification authority is loaded
// before routing stores are composed. Missing or malformed authority therefore
// prevents a usable routing runtime from being returned.
func Open(cfg Config) (*Runtime, error) {
	stateDir := strings.TrimSpace(cfg.StateDir)

	if stateDir == "" ||
		cfg.Identity == nil ||
		strings.TrimSpace(cfg.Identity.ID) == "" ||
		cfg.EndpointHandler == nil {
		return nil, ErrConfig
	}

	// Stage 3 has an explicit trusted-device model only. Do not silently turn
	// an unsupported organization/public policy into weaker authorization.
	if !cfg.RouterPolicy.TrustedDevicesOnly ||
		cfg.RouterPolicy.PublicRouting {
		return nil, ErrUnsupportedPolicy
	}

	if err := cfg.RouterPolicy.Validate(); err != nil {
		return nil, fmt.Errorf(
			"%w: router policy: %v",
			ErrConfig,
			err,
		)
	}

	switch cfg.DestinationTransport {
	case mesh.TransportLAN, mesh.TransportInternet:
	default:
		return nil, ErrUnsupportedTransport
	}

	authority, err :=
		meshstate.OpenRouteAuthorizationAuthority(stateDir)
	if err != nil {
		return nil, fmt.Errorf(
			"meshruntime: load route authorization authority: %w",
			err,
		)
	}

	replay, err := meshstate.OpenFileRouteAuthorizationReplay(
		filepath.Join(
			stateDir,
			RouteAuthorizationReplayFile,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"meshruntime: open route replay state: %w",
			err,
		)
	}

	sourceRouters, err :=
		meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		return nil, fmt.Errorf(
			"meshruntime: open source-router trust: %w",
			err,
		)
	}

	routerSources, err :=
		meshnet.OpenRouteRouterSourcesTrust(stateDir)
	if err != nil {
		return nil, fmt.Errorf(
			"meshruntime: open router-source trust: %w",
			err,
		)
	}

	routerDestinations, err :=
		meshnet.OpenRouteRouterDestinationsTrust(stateDir)
	if err != nil {
		return nil, fmt.Errorf(
			"meshruntime: open router-destination trust: %w",
			err,
		)
	}

	destinationRouters, err :=
		meshnet.OpenRouteDestinationRoutersTrust(stateDir)
	if err != nil {
		return nil, fmt.Errorf(
			"meshruntime: open destination-router trust: %w",
			err,
		)
	}

	sourceResolver := &meshnet.TrustedPeerResolver{
		Store:               sourceRouters,
		LANDiscoveryTimeout: cfg.LANDiscoveryTimeout,
	}

	routerDestinationResolver := &meshnet.TrustedPeerResolver{
		Store:               routerDestinations,
		LANDiscoveryTimeout: cfg.LANDiscoveryTimeout,
	}

	forwardDialer := meshnet.ForwardDialer{
		Identity: cfg.Identity,
		Resolver: routerDestinationResolver,
	}

	localAuthorizer := trustedSourceForwardAuthorizer{
		Store: routerSources,
	}

	signedAuthorizer := mesh.RouteAuthorizationForwardAuthorizer{
		LocalAuthorizer: localAuthorizer,
		Verifier: mesh.RouteAuthorizationVerifier{
			KeyID:     authority.KeyID,
			PublicKey: authority.PublicKey,
			Replay:    replay,
		},
	}

	router := &mesh.Forwarder{
		LocalID:    mesh.DeviceID(cfg.Identity.ID),
		Policy:     cfg.RouterPolicy,
		Authorizer: signedAuthorizer,
		DialNext:   forwardDialer.DialNext,
	}

	destination := meshnet.DestinationIngress{
		Identity:       cfg.Identity,
		TrustedRouters: destinationRouters,
		Transport:      cfg.DestinationTransport,
		Handler:        cfg.EndpointHandler,
	}

	return &Runtime{
		Identity: cfg.Identity,

		Authority: authority,
		Replay:    replay,

		SourceRouters:      sourceRouters,
		RouterSources:      routerSources,
		RouterDestinations: routerDestinations,
		DestinationRouters: destinationRouters,

		SourceRouterResolver:      sourceResolver,
		RouterDestinationResolver: routerDestinationResolver,

		Router:      router,
		Destination: destination,
	}, nil
}

// ServeRouteControl handles one already-accepted raw A -> B connection.
//
// This method still does not listen or accept sockets itself. It authenticates
// A using the router-source trust domain and the route-control TLS role before
// any WDRT request is parsed.
func (r *Runtime) ServeRouteControl(
	ctx context.Context,
	raw net.Conn,
	transport mesh.TransportName,
) (mesh.ForwardResult, error) {
	if raw == nil {
		return mesh.ForwardResult{}, ErrConfig
	}

	if r == nil ||
		r.Identity == nil ||
		r.RouterSources == nil ||
		r.Router == nil {
		_ = raw.Close()
		return mesh.ForwardResult{}, ErrConfig
	}

	switch transport {
	case mesh.TransportLAN, mesh.TransportInternet:
	default:
		_ = raw.Close()
		return mesh.ForwardResult{}, ErrUnsupportedTransport
	}

	link, err := meshnet.AcceptRouteControlLink(
		ctx,
		raw,
		r.Identity,
		r.RouterSources,
		transport,
	)
	if err != nil {
		// AcceptRouteControlLink owns raw and closes it on failure.
		return mesh.ForwardResult{}, err
	}

	return r.Router.ServeRouteOpen(ctx, link)
}

// ServeRouteTunnel handles one already-accepted raw B -> C connection.
//
// DestinationIngress authenticates B against the destination-router trust
// domain before handing the opaque inner A <-> C endpoint stream to the
// existing endpoint session handler.
func (r *Runtime) ServeRouteTunnel(
	ctx context.Context,
	raw net.Conn,
) error {
	if raw == nil {
		return ErrConfig
	}

	if r == nil {
		_ = raw.Close()
		return ErrConfig
	}

	return r.Destination.Serve(ctx, raw)
}

// trustedSourceForwardAuthorizer is B's Stage-3 local authorization policy.
//
// Authentication of A's neighboring TLS link and the signed capability are
// independent requirements. This adapter enforces the local explicit trust
// relationship before the capability verifier is allowed to consume its JTI.
type trustedSourceForwardAuthorizer struct {
	Store *trust.Store
}

var _ mesh.ForwardAuthorizer = trustedSourceForwardAuthorizer{}

func (a trustedSourceForwardAuthorizer) AuthorizeForward(
	ctx context.Context,
	request mesh.ForwardRequest,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if a.Store == nil ||
		!request.Policy.TrustedDevicesOnly ||
		request.Policy.PublicRouting {
		return mesh.ErrForwardDenied
	}

	sourceID := strings.TrimSpace(string(request.Route.Source))
	if sourceID == "" ||
		sourceID != string(request.Route.Source) {
		return mesh.ErrForwardDenied
	}

	peer, ok := a.Store.Get(sourceID)
	if !ok || peer.ID != sourceID {
		return mesh.ErrForwardDenied
	}

	if _, err := identity.ParseFingerprint(peer.Fingerprint); err != nil {
		return mesh.ErrForwardDenied
	}

	return nil
}

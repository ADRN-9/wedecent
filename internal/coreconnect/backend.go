package coreconnect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/relayauth"
	"wedecent.com/wedecent/internal/session"
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

const (
	defaultLANDiscoveryTimeout = 1500 * time.Millisecond
	directProbeTimeout         = 3 * time.Second
)

// RouteRequestSource is an internal policy hook. The UI never supplies router,
// hop, cost, or transport data. A future route-planning service may implement
// this interface and hand the backend one exact route-authorization request.
type RouteRequestSource interface {
	RouteRequest(context.Context, string, string) (account.RouteAuthorizationRequest, bool, error)
}

type findTrustedFunc func(context.Context, string, string) (discovery.Result, bool, error)

type terminalOpenerFunc func(context.Context, *identity.Identity, *trust.Store, trust.Peer, transport.Dialer, string) (coreapi.ConnectionHandle, error)

type Config struct {
	StateDir     string
	Identity     *identity.Identity
	Trust        *trust.Store
	Authorizer   coreapi.ConnectionAuthorizer
	RouteSource  RouteRequestSource
	LANTimeout   time.Duration
	RelayOptions transport.RelayOptions

	FindTrusted  findTrustedFunc
	OpenTerminal terminalOpenerFunc
	Now          func() time.Time
}

type Backend struct {
	stateDir     string
	identity     *identity.Identity
	trust        *trust.Store
	authorizer   coreapi.ConnectionAuthorizer
	routeSource  RouteRequestSource
	lanTimeout   time.Duration
	relayOptions transport.RelayOptions
	findTrusted  findTrustedFunc
	openTerminal terminalOpenerFunc
	now          func() time.Time
}

var _ coreapi.ConnectionBackend = (*Backend)(nil)

func New(cfg Config) (*Backend, error) {
	stateDir := strings.TrimSpace(cfg.StateDir)
	if stateDir == "" {
		return nil, errors.New("core connection backend: state directory is required")
	}
	if cfg.Identity == nil {
		return nil, errors.New("core connection backend: identity is required")
	}
	if cfg.Trust == nil {
		return nil, errors.New("core connection backend: terminal trust store is required")
	}
	if cfg.Authorizer == nil {
		return nil, errors.New("core connection backend: authorizer is required")
	}
	lanTimeout := cfg.LANTimeout
	if lanTimeout == 0 {
		lanTimeout = defaultLANDiscoveryTimeout
	}
	if lanTimeout < 0 || lanTimeout > 10*time.Second {
		return nil, errors.New("core connection backend: LAN timeout must be between 0 and 10s")
	}
	findTrusted := cfg.FindTrusted
	if findTrusted == nil {
		findTrusted = discovery.FindTrusted
	}
	openTerminal := cfg.OpenTerminal
	if openTerminal == nil {
		openTerminal = openManagedTerminal
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	relayOptions := cfg.RelayOptions
	if relayOptions.Timeout <= 0 {
		relayOptions.Timeout = 10 * time.Second
	}
	return &Backend{
		stateDir:     stateDir,
		identity:     cfg.Identity,
		trust:        cfg.Trust,
		authorizer:   cfg.Authorizer,
		routeSource:  cfg.RouteSource,
		lanTimeout:   lanTimeout,
		relayOptions: relayOptions,
		findTrusted:  findTrusted,
		openTerminal: openTerminal,
		now:          now,
	}, nil
}

func (b *Backend) Open(ctx context.Context, destinationDeviceID string) (coreapi.OpenedConnection, error) {
	if err := ctx.Err(); err != nil {
		return coreapi.OpenedConnection{}, err
	}
	destinationDeviceID = strings.TrimSpace(destinationDeviceID)
	peer, ok := b.trust.Get(destinationDeviceID)
	if !ok {
		return coreapi.OpenedConnection{}, errors.New("destination is not paired")
	}

	if b.routeSource != nil {
		request, routed, err := b.routeSource.RouteRequest(ctx, b.identity.ID, destinationDeviceID)
		if err != nil {
			return coreapi.OpenedConnection{}, err
		}
		if routed {
			return b.openRouted(ctx, peer, request)
		}
	}

	selectedPeer, path, err := b.selectNonRoutedPath(ctx, peer)
	if err != nil {
		return coreapi.OpenedConnection{}, err
	}
	grant, err := b.authorizer.IssueConnectionGrant(ctx, b.identity.ID, destinationDeviceID)
	if err != nil {
		return coreapi.OpenedConnection{}, err
	}

	webRelayGrant := ""
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(selectedPeer.Endpoint)), "wsrelay://") {
		webRelayGrant = grant
	}
	dialer := transport.MultiDialer{
		Relay: b.relayOptions,
		WebRelay: transport.WebRelayOptions{
			TicketSource:    relayauth.NewTicketSource(b.identity),
			ConnectionGrant: webRelayGrant,
			Timeout:         15 * time.Second,
		},
	}
	handle, err := b.openTerminal(ctx, b.identity, b.trust, selectedPeer, dialer, grant)
	if err != nil {
		return coreapi.OpenedConnection{}, err
	}
	return coreapi.OpenedConnection{Path: path, Handle: handle}, nil
}

func (b *Backend) openRouted(ctx context.Context, peer trust.Peer, request account.RouteAuthorizationRequest) (coreapi.OpenedConnection, error) {
	if strings.TrimSpace(request.SourceDeviceID) != b.identity.ID ||
		strings.TrimSpace(request.DestinationDeviceID) != peer.ID {
		return coreapi.OpenedConnection{}, errors.New("routed request does not match local connection")
	}

	// Preserve the existing CLI order: acquire the terminal grant first, then
	// validate local router trust and request the distinct route capability.
	grant, err := b.authorizer.IssueConnectionGrant(ctx, b.identity.ID, peer.ID)
	if err != nil {
		return coreapi.OpenedConnection{}, err
	}
	routerTrust, err := meshnet.OpenRouteSourceRoutersTrust(b.stateDir)
	if err != nil {
		return coreapi.OpenedConnection{}, fmt.Errorf("open source routing trust: %w", err)
	}
	if _, ok := routerTrust.Get(strings.TrimSpace(request.RouterDeviceID)); !ok {
		return coreapi.OpenedConnection{}, errors.New("selected router is not trusted for routing")
	}

	route, authorization, err := b.authorizer.IssueRouteAuthorization(ctx, request)
	if err != nil {
		return coreapi.OpenedConnection{}, err
	}
	if err := validateRoutedResult(b.identity.ID, peer.ID, route, authorization, b.now()); err != nil {
		return coreapi.OpenedConnection{}, err
	}
	dialer := meshnet.RoutedDialer{
		Identity: b.identity,
		Resolver: meshnet.TrustedPeerResolver{
			Store:               routerTrust,
			LANDiscoveryTimeout: b.lanTimeout,
		},
		Route:         route,
		Authorization: authorization,
		Now:           b.now,
	}
	handle, err := b.openTerminal(ctx, b.identity, b.trust, peer, dialer, grant)
	if err != nil {
		return coreapi.OpenedConnection{}, err
	}
	routeCopy := route
	routeCopy.Hops = append([]mesh.RouteHop(nil), route.Hops...)
	return coreapi.OpenedConnection{Path: v1.ConnectionPathRouted, Route: &routeCopy, Handle: handle}, nil
}

func (b *Backend) selectNonRoutedPath(ctx context.Context, peer trust.Peer) (trust.Peer, v1.ConnectionPath, error) {
	endpoint := strings.TrimSpace(peer.Endpoint)
	if b.lanTimeout > 0 && (endpoint == "" || hasRelayScheme(endpoint)) {
		lanCtx, cancel := context.WithTimeout(ctx, b.lanTimeout)
		result, found, discoverErr := b.findTrusted(lanCtx, peer.ID, peer.Fingerprint)
		cancel()
		if discoverErr != nil && errors.Is(discoverErr, discovery.ErrTrustedIdentityMismatch) {
			return trust.Peer{}, "", discoverErr
		}
		if found {
			locator, locatorErr := directLocator(result.Endpoint)
			if locatorErr == nil {
				directPeer := peer
				directPeer.Endpoint = locator
				probeDialer := transport.MultiDialer{Relay: transport.RelayOptions{Timeout: 2 * time.Second}}
				probeClient := &session.Client{Identity: b.identity, Trust: b.trust, Dialer: probeDialer}
				probeCtx, probeCancel := context.WithTimeout(ctx, directProbeTimeout)
				probeErr := probeClient.Probe(probeCtx, directPeer)
				probeCancel()
				if probeErr == nil {
					return directPeer, v1.ConnectionPathLAN, nil
				}
			}
		}
	}

	if endpoint == "" {
		return trust.Peer{}, "", errors.New("device has no connection locator")
	}
	peer.Endpoint = endpoint
	if hasRelayScheme(endpoint) {
		return peer, v1.ConnectionPathRelay, nil
	}
	if strings.HasPrefix(strings.ToLower(endpoint), "tcp://") || !strings.Contains(endpoint, "://") {
		return peer, v1.ConnectionPathDirect, nil
	}
	return trust.Peer{}, "", errors.New("device has unsupported connection locator")
}

func openManagedTerminal(ctx context.Context, id *identity.Identity, store *trust.Store, peer trust.Peer, dialer transport.Dialer, grant string) (coreapi.ConnectionHandle, error) {
	client := &session.Client{
		Identity:        id,
		Trust:           store,
		Dialer:          dialer,
		ConnectionGrant: grant,
	}
	return client.OpenManagedTerminal(ctx, peer, 80, 24, "")
}

func hasRelayScheme(endpoint string) bool {
	endpoint = strings.ToLower(strings.TrimSpace(endpoint))
	return strings.HasPrefix(endpoint, "relay://") || strings.HasPrefix(endpoint, "wsrelay://")
}

func directLocator(endpoint string) (string, error) {
	hostPort := strings.TrimPrefix(strings.TrimSpace(endpoint), "tcp://")
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", errors.New("address must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("port must be between 1 and 65535")
	}
	return "tcp://" + net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func validateRoutedResult(sourceID, destinationID string, route mesh.Route, authorization mesh.RouteAuthorization, now time.Time) error {
	if err := route.Validate(now); err != nil {
		return fmt.Errorf("invalid routed connection route: %w", err)
	}
	if len(route.Hops) != 2 {
		return errors.New("routed connection requires exactly two route hops")
	}
	if route.Source != mesh.DeviceID(sourceID) || route.Destination != mesh.DeviceID(destinationID) || route.Hops[0].From != mesh.DeviceID(sourceID) {
		return errors.New("routed connection route does not match requested endpoints")
	}
	claims := authorization.Claims
	if claims.ExpiresUnixMS <= now.UTC().UnixMilli() {
		return errors.New("route authorization is expired")
	}
	if route.ExpiresAt.UTC().UnixMilli() != claims.ExpiresUnixMS || claims.Router != route.Hops[0].To {
		return errors.New("route authorization does not match route")
	}
	claimed := claims.Route
	if claimed.ID != route.ID || claimed.Source != route.Source || claimed.Destination != route.Destination ||
		claimed.ExpiresAt.UTC().UnixMilli() != route.ExpiresAt.UTC().UnixMilli() || len(claimed.Hops) != len(route.Hops) {
		return errors.New("route authorization does not match route")
	}
	for i := range route.Hops {
		got, want := route.Hops[i], claimed.Hops[i]
		if got.From != want.From || got.To != want.To || got.Transport != want.Transport || got.Cost != want.Cost {
			return errors.New("route authorization does not match route")
		}
	}
	return nil
}

package coreconnect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/portforward"
	"wedecent.com/wedecent/internal/session"
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

// OpenPortForwarding opens one authenticated TLS parent carrying a signed
// forwarding capability. The capability and separate route authorization are
// passed unchanged to the destination; this method never substitutes locator
// metadata for endpoint identity.
func (b *Backend) OpenPortForwarding(ctx context.Context, auth portforward.Authorization) (portforward.ForwardingSession, error) {
	if b == nil || ctx == nil || b.identity == nil || b.trust == nil || b.authorizer == nil {
		return nil, errors.New("core forwarding backend is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	claims := auth.Claims
	if err := portforward.ValidateClaims(claims); err != nil {
		return nil, err
	}
	if err := portforward.ValidateRouteAuthorizationBinding(auth); err != nil {
		return nil, err
	}
	localID := mesh.DeviceID(b.identity.ID)
	if portforward.ListenerDevice(claims) != localID {
		return nil, portforward.ErrAuthorizationMismatch
	}
	remoteID := claims.DestinationDevice
	if claims.Direction == portforward.DirectionRemote {
		remoteID = claims.InitiatingDevice
	}
	if claims.Route.Source != localID || claims.Route.Destination != remoteID {
		return nil, portforward.ErrAuthorizationMismatch
	}
	peer, ok := b.trust.Get(string(remoteID))
	if !ok {
		return nil, errors.New("forwarding destination is not trusted")
	}
	grant, err := b.authorizer.IssueConnectionGrant(ctx, b.identity.ID, peer.ID)
	if err != nil {
		return nil, err
	}

	var dialer transport.Dialer
	if claims.Router != "" {
		routerTrust, err := meshnet.OpenRouteSourceRoutersTrust(b.stateDir)
		if err != nil {
			return nil, fmt.Errorf("open source routing trust: %w", err)
		}
		if _, ok := routerTrust.Get(string(claims.Router)); !ok {
			return nil, errors.New("forwarding router is not trusted for routing")
		}
		if err := validateRoutedResult(b.identity.ID, peer.ID, claims.Route, auth.RouteAuthorization, b.now()); err != nil {
			return nil, err
		}
		dialer = meshnet.RoutedDialer{
			Identity: b.identity,
			Resolver: meshnet.TrustedPeerResolver{
				Store: routerTrust, LANDiscoveryTimeout: b.lanTimeout,
			},
			Route: claims.Route, Authorization: auth.RouteAuthorization, Now: b.now,
		}
	} else {
		if len(claims.Route.Hops) != 1 {
			return nil, portforward.ErrAuthorizationMismatch
		}
		selectedPeer, _, err := b.selectNonRoutedPath(ctx, peer)
		if err != nil {
			return nil, err
		}
		relayGrant := ""
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(selectedPeer.Endpoint)), "wsrelay://") {
			relayGrant = grant
		}
		dialer = transport.MultiDialer{
			Relay: b.relayOptions,
			WebRelay: transport.WebRelayOptions{
				TicketSource: relayauth.NewTicketSource(b.identity),
				ConnectionGrant: relayGrant,
				Timeout: 15 * time.Second,
			},
		}
		peer = selectedPeer
	}

	client := &session.Client{
		Identity: b.identity, Trust: b.trust, Dialer: dialer, ConnectionGrant: grant,
	}
	return client.OpenManagedPortForwardSession(ctx, peer, auth)
}

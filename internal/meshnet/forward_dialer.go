package meshnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
)

var (
	ErrForwardDialerConfig = errors.New("meshnet: invalid forwarding-dialer configuration")
	ErrForwardHopInvalid   = errors.New("meshnet: invalid forwarding hop")
	ErrForwardPeerMismatch = errors.New("meshnet: resolved forwarding peer does not match hop")
)

// ForwardDialer opens the router's authenticated B -> C neighboring link.
//
// It deliberately receives only a mesh.RouteHop. The route carries device IDs
// and a transport name, never a host:port. C's locator and pinned fingerprint
// come exclusively from Resolver, which is backed by router-owned trusted
// state and, for LAN, fingerprint-pinned signed discovery.
type ForwardDialer struct {
	Identity *identity.Identity
	Resolver PeerResolver

	// DialTCP exists for deterministic tests. Production callers normally leave
	// it nil and use the same direct TCP dial helper as RoutedDialer.
	DialTCP func(context.Context, string) (net.Conn, error)
}

// DialNext satisfies mesh.ForwardDialFunc.
//
// The returned link always uses the destination-tunnel TLS role. It must never
// negotiate the route-control role used by A -> B.
func (d ForwardDialer) DialNext(
	ctx context.Context,
	hop mesh.RouteHop,
) (mesh.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.Identity == nil || d.Resolver == nil {
		return nil, ErrForwardDialerConfig
	}

	localID := mesh.DeviceID(strings.TrimSpace(d.Identity.ID))
	if localID == "" ||
		hop.From != localID ||
		strings.TrimSpace(string(hop.To)) == "" ||
		strings.TrimSpace(string(hop.Transport)) == "" ||
		hop.From == hop.To {
		return nil, ErrForwardHopInvalid
	}

	peer, err := d.Resolver.Resolve(
		ctx,
		hop.To,
		hop.Transport,
	)
	if err != nil {
		return nil, err
	}

	// A resolver implementation is still treated as untrusted input at this
	// seam. It may choose network metadata, but it may not redirect the hop to
	// another identity or transport.
	if peer.ID != hop.To || peer.Transport != hop.Transport {
		return nil, ErrForwardPeerMismatch
	}

	address, err := routedTCPAddress(peer.Locator)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: trusted destination locator: %v",
			ErrForwardDialerConfig,
			err,
		)
	}

	dialTCP := d.DialTCP
	if dialTCP == nil {
		dialTCP = defaultRoutedTCPDial
	}

	raw, err := dialTCP(ctx, address)
	if err != nil {
		return nil, fmt.Errorf(
			"meshnet: dial trusted routed destination: %w",
			err,
		)
	}

	link, err := DialRouteTunnelLink(
		ctx,
		raw,
		d.Identity,
		peer,
	)
	if err != nil {
		// DialRouteTunnelLink owns and closes raw on failure.
		return nil, err
	}

	// Defense in depth. DialRouteTunnelLink already cryptographically binds the
	// peer identity and transport metadata, and Forwarder checks these fields
	// again before copying any bytes.
	if link.Local() != localID ||
		link.Remote() != hop.To ||
		link.Transport() != hop.Transport {
		_ = link.Close()
		return nil, ErrForwardPeerMismatch
	}

	return link, nil
}

var _ mesh.ForwardDialFunc = (ForwardDialer{}).DialNext

package meshnet

import (
	"context"
	"errors"
	"net"
	"strings"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/trust"
)

var ErrDestinationIngressConfig = errors.New(
	"meshnet: invalid routed destination ingress configuration",
)

// EndpointConnHandler is the narrow handoff boundary between authenticated
// mesh ingress and the existing endpoint session server.
//
// session.Server satisfies this interface structurally via ServeConn(net.Conn),
// without meshnet importing the session package.
type EndpointConnHandler interface {
	ServeConn(net.Conn)
}

// DestinationIngress authenticates a B -> C route-tunnel connection before
// handing its decrypted outer stream to C's endpoint-session handler.
//
// TrustedRouters is deliberately separate from ordinary terminal-client trust.
// A device being allowed to open an endpoint session must not implicitly make
// it a trusted routing neighbor.
//
// Serve takes ownership of raw.
type DestinationIngress struct {
	Identity       *identity.Identity
	TrustedRouters *trust.Store
	Transport      mesh.TransportName
	Handler        EndpointConnHandler
}

// Serve authenticates the outer B -> C route-tunnel TLS role, then transfers
// the resulting net.Conn to Handler. The handler starts the inner A <-> C
// endpoint TLS connection.
//
// No route-control framing is accepted or parsed here.
func (i DestinationIngress) Serve(
	ctx context.Context,
	raw net.Conn,
) error {
	if raw == nil {
		return ErrDestinationIngressConfig
	}

	if err := ctx.Err(); err != nil {
		_ = raw.Close()
		return err
	}

	if i.Identity == nil ||
		i.TrustedRouters == nil ||
		i.Handler == nil ||
		strings.TrimSpace(string(i.Transport)) == "" {
		_ = raw.Close()
		return ErrDestinationIngressConfig
	}

	link, err := AcceptRouteTunnelLink(
		ctx,
		raw,
		i.Identity,
		i.TrustedRouters,
		i.Transport,
	)
	if err != nil {
		// AcceptRouteTunnelLink owns and closes raw on failure.
		return err
	}
	defer link.Close()

	// Ownership is scoped to this call. session.Server.ServeConn also closes
	// its input when it returns; closing twice is harmless and guarantees that
	// alternate handlers cannot leak the authenticated outer connection.
	i.Handler.ServeConn(link)

	return nil
}

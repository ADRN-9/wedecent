package coreconnect

import (
	"context"
	"errors"

	"wedecent.com/wedecent/internal/portforward"
)

// ForwardingBackend is the Local Core transport authority used by the
// portforward.Manager. It shares the same identity, trust and route selection
// implementation as terminal connections.
type ForwardingBackend interface {
	OpenPortForwarding(context.Context, portforward.Authorization) (portforward.ForwardingSession, error)
}

type ForwardingConnector struct {
	Backend ForwardingBackend
}

func (c ForwardingConnector) Open(ctx context.Context, auth portforward.Authorization) (portforward.ForwardingSession, error) {
	if c.Backend == nil {
		return nil, errors.New("core forwarding connector is unavailable")
	}
	return c.Backend.OpenPortForwarding(ctx, auth)
}

var _ portforward.Connector = ForwardingConnector{}

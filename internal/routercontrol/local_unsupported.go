//go:build !windows

package routercontrol

import (
	"context"
	"net"
)

func ListenLocal() (net.Listener, error) {
	return nil, ErrLocalEndpointUnsupported
}

func DialLocal(context.Context) (net.Conn, error) {
	return nil, ErrLocalEndpointUnsupported
}

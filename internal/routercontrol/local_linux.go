//go:build linux

package routercontrol

import (
	"context"
	"fmt"
	"net"
)

const linuxRouterAdminSocket = "@wedecent-router-admin-v1"

// ListenLocal binds the fixed machine-local Linux router-admin endpoint.
// Linux abstract Unix sockets avoid filesystem ownership and symlink races
// between an agent service identity and an interactive Local Core user.
// Opening this byte stream is not authorization; mTLS and controller trust
// remain mandatory before any router-admin request is accepted.
func ListenLocal() (net.Listener, error) {
	return listenLinuxRouterAdmin(linuxRouterAdminSocket)
}

func DialLocal(ctx context.Context) (net.Conn, error) {
	return dialLinuxRouterAdmin(ctx, linuxRouterAdminSocket)
}

func listenLinuxRouterAdmin(address string) (net.Listener, error) {
	listener, err := net.Listen("unix", address)
	if err != nil {
		return nil, fmt.Errorf("routercontrol: listen local admin socket: %w", err)
	}
	return listener, nil
}

func dialLinuxRouterAdmin(ctx context.Context, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", address)
	if err != nil {
		return nil, fmt.Errorf("routercontrol: dial local admin socket: %w", err)
	}
	return conn, nil
}

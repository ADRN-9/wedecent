//go:build windows

package routercontrol

import (
	"context"
	"fmt"
	"net"

	winio "github.com/Microsoft/go-winio"
)

const (
	windowsRouterAdminPipe = `\\.\pipe\WeDecent.RouterAdmin.v1`

	// The pipe is machine-local and rejects remote clients in go-winio. Local
	// authenticated users may open the byte stream, but router administration
	// still requires the dedicated mutually authenticated TLS controller trust
	// domain before any request is parsed.
	windowsRouterAdminSDDL = `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)`
)

func ListenLocal() (net.Listener, error) {
	listener, err := winio.ListenPipe(windowsRouterAdminPipe, &winio.PipeConfig{
		SecurityDescriptor: windowsRouterAdminSDDL,
		MessageMode:        false,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("routercontrol: listen local admin pipe: %w", err)
	}
	return listener, nil
}

func DialLocal(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := winio.DialPipeContext(ctx, windowsRouterAdminPipe)
	if err != nil {
		return nil, fmt.Errorf("routercontrol: dial local admin pipe: %w", err)
	}
	return conn, nil
}

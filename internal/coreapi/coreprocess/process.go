package coreprocess

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/coreapi"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	"wedecent.com/wedecent/internal/coreapi/localipc"
	"wedecent.com/wedecent/internal/coreapi/localserver"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/trust"
)

var ErrServerRequired = errors.New("core process: IPC server is required")

// OpenReadOnly composes the current read-only Local Core API from existing
// client state. It never creates or renews device identity material and it does
// not refresh or persist account credentials.
func OpenReadOnly(clientStateDir string) (*ipc.Server, error) {
	id, err := identity.Load(clientStateDir)
	if err != nil {
		return nil, fmt.Errorf("core process: load identity: %w", err)
	}

	session, err := account.Load(account.SessionPath(clientStateDir))
	if errors.Is(err, account.ErrNoSession) {
		session = nil
	} else if err != nil {
		return nil, fmt.Errorf("core process: load account session: %w", err)
	}

	devices, err := trust.Open(filepath.Join(clientStateDir, "trusted-devices.json"))
	if err != nil {
		return nil, fmt.Errorf("core process: open device trust: %w", err)
	}
	service, err := coreapi.NewReadService(id, session, devices)
	if err != nil {
		return nil, fmt.Errorf("core process: compose read service: %w", err)
	}
	server, err := ipc.NewServer(service, service)
	if err != nil {
		return nil, fmt.Errorf("core process: compose IPC server: %w", err)
	}
	return server, nil
}

// RunLocal serves the read-only Local Core API over the protected per-user IPC
// transport using the shared bounded server lifecycle. No IP listener is opened.
func RunLocal(ctx context.Context, server *ipc.Server) error {
	if server == nil {
		return ErrServerRequired
	}
	listener, err := localipc.Listen()
	if err != nil {
		return fmt.Errorf("core process: listen: %w", err)
	}
	return localserver.Serve(ctx, listener, server.ServeOne, localserver.DefaultConfig())
}

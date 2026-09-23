package coreprocess

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/coreapi"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	"wedecent.com/wedecent/internal/coreapi/localipc"
	"wedecent.com/wedecent/internal/coreapi/localserver"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/coreconnect"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/trust"
)

var ErrServerRequired = errors.New("core process: IPC server is required")

type Config struct {
	ClientStateDir    string
	SupabaseURL       string
	PublishableKey    string
	AccountClient     coreapi.AccountClient
	ConnectionBackend coreapi.ConnectionBackend
	RouteSource       coreconnect.RouteRequestSource
	RouterService     v1.RouterService
}

// Runtime owns the Local Core IPC server plus process-scoped connection
// lifecycle. Closing it cancels in-flight opens and tears down active sessions.
type Runtime struct {
	Server      *ipc.Server
	Connections *coreapi.ConnectionService
}

func (r *Runtime) Close() error {
	if r == nil || r.Connections == nil {
		return nil
	}
	return r.Connections.Close()
}

// Open composes the Local Core API from existing client state. Identity state is
// never created or renewed. Account credentials are accepted only by the account
// service and returned auth tokens remain inside the core/session store.
func Open(cfg Config) (*ipc.Server, error) {
	runtime, err := OpenRuntime(cfg)
	if err != nil {
		return nil, err
	}
	return runtime.Server, nil
}

// OpenRuntime composes the process-owned networking lifecycle used by wd-core.
func OpenRuntime(cfg Config) (*Runtime, error) {
	stateDir := strings.TrimSpace(cfg.ClientStateDir)
	if stateDir == "" {
		return nil, errors.New("core process: client state directory is required")
	}
	supabaseURL := strings.TrimSpace(cfg.SupabaseURL)
	publishableKey := strings.TrimSpace(cfg.PublishableKey)
	if (supabaseURL == "") != (publishableKey == "") {
		return nil, errors.New("core process: Supabase URL and publishable key must be configured together")
	}

	id, err := identity.Load(stateDir)
	if err != nil {
		return nil, fmt.Errorf("core process: load identity: %w", err)
	}

	sessionPath := account.SessionPath(stateDir)
	accountSession, err := account.Load(sessionPath)
	if errors.Is(err, account.ErrNoSession) {
		accountSession = nil
	} else if err != nil {
		return nil, fmt.Errorf("core process: load account session: %w", err)
	}

	devices, err := trust.Open(filepath.Join(stateDir, "trusted-devices.json"))
	if err != nil {
		return nil, fmt.Errorf("core process: open device trust: %w", err)
	}
	readService, err := coreapi.NewReadService(id, accountSession, devices)
	if err != nil {
		return nil, fmt.Errorf("core process: compose read service: %w", err)
	}
	networkService, err := coreapi.NewNetworkReadService(id.ID, coreapi.DefaultTransportStatuses())
	if err != nil {
		return nil, fmt.Errorf("core process: compose network read service: %w", err)
	}

	if supabaseURL == "" && accountSession != nil {
		supabaseURL = accountSession.SupabaseURL
		publishableKey = accountSession.PublishableKey
	}
	accountClient := cfg.AccountClient
	if accountClient == nil {
		accountClient = account.Client{}
	}
	accountService, err := coreapi.NewAccountService(coreapi.AccountServiceConfig{
		Client:         accountClient,
		SupabaseURL:    supabaseURL,
		PublishableKey: publishableKey,
		SessionPath:    sessionPath,
		Status:         readService,
		InitialSession: accountSession,
	})
	if err != nil {
		return nil, fmt.Errorf("core process: compose account service: %w", err)
	}

	connectionBackend := cfg.ConnectionBackend
	if connectionBackend == nil {
		routeSource := cfg.RouteSource
		if routeSource == nil {
			routeSource, err = coreconnect.NewPolicyRouteSource(stateDir)
			if err != nil {
				return nil, fmt.Errorf("core process: compose route selection source: %w", err)
			}
		}
		connectionBackend, err = coreconnect.New(coreconnect.Config{
			StateDir:    stateDir,
			Identity:    id,
			Trust:       devices,
			Authorizer:  accountService,
			RouteSource: routeSource,
		})
		if err != nil {
			return nil, fmt.Errorf("core process: compose connection backend: %w", err)
		}
	}
	connectionService, err := coreapi.NewConnectionService(coreapi.ConnectionServiceConfig{
		Backend: connectionBackend,
		Network: networkService,
	})
	if err != nil {
		return nil, fmt.Errorf("core process: compose connection service: %w", err)
	}

	server, err := ipc.NewServerWithServices(ipc.Services{
		Status:      readService,
		Devices:     readService,
		Account:     accountService,
		Connections: connectionService,
		Transports:  networkService,
		Routes:      networkService,
		Router:      cfg.RouterService,
	})
	if err != nil {
		_ = connectionService.Close()
		return nil, fmt.Errorf("core process: compose IPC server: %w", err)
	}
	return &Runtime{Server: server, Connections: connectionService}, nil
}

// OpenReadOnly preserves a credential-free composition for callers that do not
// want account mutations. It still exposes non-secret status, device, transport,
// and route readers.
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
	networkService, err := coreapi.NewNetworkReadService(id.ID, coreapi.DefaultTransportStatuses())
	if err != nil {
		return nil, fmt.Errorf("core process: compose network read service: %w", err)
	}
	server, err := ipc.NewServerWithServices(ipc.Services{
		Status:     service,
		Devices:    service,
		Transports: networkService,
		Routes:     networkService,
	})
	if err != nil {
		return nil, fmt.Errorf("core process: compose IPC server: %w", err)
	}
	return server, nil
}

// RunLocal serves the Local Core API over the protected per-user IPC transport
// using the shared bounded server lifecycle. No IP listener is opened.
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

// RunLocalRuntime is the process entry point used by wd-core. It closes the
// connection service after the bounded local server has drained request
// handlers, ensuring active sessions and any in-flight opens are torn down.
func RunLocalRuntime(ctx context.Context, runtime *Runtime) error {
	if runtime == nil || runtime.Server == nil {
		return ErrServerRequired
	}
	serveErr := RunLocal(ctx, runtime.Server)
	closeErr := runtime.Close()
	if serveErr != nil {
		if closeErr != nil {
			return errors.Join(serveErr, closeErr)
		}
		return serveErr
	}
	return closeErr
}

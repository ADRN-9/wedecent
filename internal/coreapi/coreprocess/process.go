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
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/trust"
)

var ErrServerRequired = errors.New("core process: IPC server is required")

type Config struct {
	ClientStateDir string
	SupabaseURL    string
	PublishableKey string
	AccountClient  coreapi.AccountClient
}

// Open composes the Local Core API from existing client state. Identity state is
// never created or renewed. Account credentials are accepted only by the account
// service and returned auth tokens remain inside the core/session store.
func Open(cfg Config) (*ipc.Server, error) {
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
	session, err := account.Load(sessionPath)
	if errors.Is(err, account.ErrNoSession) {
		session = nil
	} else if err != nil {
		return nil, fmt.Errorf("core process: load account session: %w", err)
	}

	devices, err := trust.Open(filepath.Join(stateDir, "trusted-devices.json"))
	if err != nil {
		return nil, fmt.Errorf("core process: open device trust: %w", err)
	}
	readService, err := coreapi.NewReadService(id, session, devices)
	if err != nil {
		return nil, fmt.Errorf("core process: compose read service: %w", err)
	}

	if supabaseURL == "" && session != nil {
		supabaseURL = session.SupabaseURL
		publishableKey = session.PublishableKey
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
		InitialSession: session,
	})
	if err != nil {
		return nil, fmt.Errorf("core process: compose account service: %w", err)
	}

	server, err := ipc.NewServerWithAccount(readService, readService, accountService)
	if err != nil {
		return nil, fmt.Errorf("core process: compose IPC server: %w", err)
	}
	return server, nil
}

// OpenReadOnly preserves the previous read-only composition for callers that do
// not want credential-bearing account methods.
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

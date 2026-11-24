package coreprocess

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/coreapi"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	"wedecent.com/wedecent/internal/coreapi/localipc"
	"wedecent.com/wedecent/internal/coreapi/localserver"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/coreconnect"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/portforward"
	"wedecent.com/wedecent/internal/trust"
)

var ErrServerRequired = errors.New("core process: IPC server is required")

type Config struct {
	ClientStateDir           string
	SupabaseURL              string
	PublishableKey           string
	AccountClient            coreapi.AccountClient
	ConnectionBackend        coreapi.ConnectionBackend
	RouteSource              coreconnect.RouteRequestSource
	RouterService            v1.RouterService
	Forwarding               *portforward.ManagerConfig
	ForwardingReplayEndpoint string // Deprecated: single-provider replay is rejected.
	ForwardingReplayAPIKey   string // Deprecated: single-provider replay is rejected.
	ForwardingCheckpointProvider *portforward.WitnessedReplayCheckpointProvider
	ForwardingMembershipResolver portforward.CheckpointMembershipResolver
	ForwardingRouteVerifier portforward.CheckpointRouteAuthorizationVerifier
}

// Runtime owns the Local Core IPC server plus process-scoped connection
// lifecycle. Closing it cancels in-flight opens and tears down active sessions.
type Runtime struct {
	Server         *ipc.Server
	Connections    *coreapi.ConnectionService
	Forwarding     *portforward.Manager
	PortForwarding *coreapi.PortForwardService
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	var errs []error
	if r.Forwarding != nil {
		errs = append(errs, r.Forwarding.Close())
	}
	if r.Connections != nil {
		errs = append(errs, r.Connections.Close())
	}
	return errors.Join(errs...)
}

func newLocalCoreForwardingVerifier(
	stateDir string,
	deviceID mesh.DeviceID,
	signer crypto.Signer,
	publicKey ed25519.PublicKey,
	provider *portforward.WitnessedReplayCheckpointProvider,
	memberships portforward.CheckpointMembershipResolver,
	routeVerifier portforward.CheckpointRouteAuthorizationVerifier,
	legacyEndpoint string,
	legacyAPIKey string,
) (*portforward.AuthorizationVerifier, error) {
	if strings.TrimSpace(legacyEndpoint) != "" || strings.TrimSpace(legacyAPIKey) != "" {
		return nil, errors.New("Local Core rejects the legacy single-provider replay path; configure an independently witnessed checkpoint provider")
	}
	if len(publicKey) != ed25519.PublicKeySize || signer == nil || provider == nil || memberships == nil {
		return nil, errors.New("production forwarding requires a witnessed checkpoint provider and independently authenticated endpoint membership resolver")
	}
	devicePublicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(devicePublicKey) != ed25519.PublicKeySize ||
		identity.DeviceID(devicePublicKey) != string(deviceID) ||
		bytes.Equal(devicePublicKey, publicKey) ||
		bytes.Equal(provider.PrimaryKey, publicKey) ||
		bytes.Equal(provider.PrimaryKey, devicePublicKey) {
		return nil, portforward.ErrCheckpointIntegrity
	}
	for _, witness := range provider.Witnesses {
		if bytes.Equal(witness.PublicKey, publicKey) || bytes.Equal(witness.PublicKey, devicePublicKey) {
			return nil, portforward.ErrCheckpointIntegrity
		}
	}
	pendingPath, err := filepath.Abs(filepath.Join(stateDir, "portforward-checkpoint-pending.json"))
	if err != nil {
		return nil, fmt.Errorf("core process: resolve witnessed pending journal: %w", err)
	}
	pending, err := portforward.NewFileCheckpointPendingStore(pendingPath)
	if err != nil {
		return nil, fmt.Errorf("core process: open witnessed pending journal: %w", err)
	}
	checkpointProvider := *provider
	checkpointProvider.Pending = pending
	if err := checkpointProvider.ValidateConfiguration(); err != nil {
		return nil, fmt.Errorf("core process: invalid witnessed checkpoint provider: %w", err)
	}
	replay := &portforward.CheckpointAuthorizationReplay{
		Provider:        &checkpointProvider,
		ControlPlaneKey: append(ed25519.PublicKey(nil), publicKey...),
		LocalDeviceID:   deviceID,
		DeviceSigner:    signer,
		Memberships:     memberships,
		RouteVerifier:   routeVerifier,
	}
	return &portforward.AuthorizationVerifier{
		PublicKey: append(ed25519.PublicKey(nil), publicKey...),
		Replay:    replay,
	}, nil
}

// Open composes the Local Core API from existing client state. Identity state is
// never created or renewed. Account credentials are accepted only by the account
// service and returned auth tokens remain inside the core/session store.
func Open(cfg Config) (*ipc.Server, error) {
	if cfg.Forwarding != nil {
		return nil, errors.New("core process: forwarding requires OpenRuntime lifecycle ownership")
	}
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

	var forwardingVerifier *portforward.AuthorizationVerifier
	if cfg.Forwarding != nil {
		if cfg.Forwarding.Verifier != nil || cfg.Forwarding.ReplayPath != "" || cfg.Forwarding.AllowFileReplay {
			return nil, errors.New("core process: Local Core forwarding forbids custom and file-backed replay verifiers")
		}
		replayPath, pathErr := filepath.Abs(filepath.Join(stateDir, "portforward-replay.json"))
		if pathErr != nil {
			return nil, fmt.Errorf("core process: resolve legacy replay path: %w", pathErr)
		}
		if replayErr := portforward.RejectExistingFileReplayState(replayPath); replayErr != nil {
			return nil, fmt.Errorf("core process: legacy file replay state requires offline preservation, capability revocation and endpoint identity recovery; see docs/PORT_FORWARDING_SECURITY.md: %w", replayErr)
		}
		forwardingVerifier, err = newLocalCoreForwardingVerifier(
			stateDir,
			mesh.DeviceID(id.ID),
			id.PrivateKey,
			cfg.Forwarding.AuthorizationPublicKey,
			cfg.ForwardingCheckpointProvider,
			cfg.ForwardingMembershipResolver,
			cfg.ForwardingRouteVerifier,
			cfg.ForwardingReplayEndpoint,
			cfg.ForwardingReplayAPIKey,
		)
		if err != nil {
			return nil, fmt.Errorf("core process: configure independent source-side replay authority: %w", err)
		}
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
	var forwardingManager *portforward.Manager
	if cfg.Forwarding != nil {
		forwardingConfig := *cfg.Forwarding
		forwardingConfig.LocalDeviceID = mesh.DeviceID(id.ID)
		if forwardingConfig.Connector == nil {
			forwardingBackend, ok := connectionBackend.(coreconnect.ForwardingBackend)
			if !ok {
				_ = connectionService.Close()
				return nil, errors.New("core process: configured connection backend does not support authenticated forwarding")
			}
			forwardingConfig.Connector = coreconnect.ForwardingConnector{Backend: forwardingBackend}
		}
		if forwardingConfig.PermissionAuthorizer == nil {
			forwardingConfig.PermissionAuthorizer = portforward.CapabilityPermissionAuthorizer{}
		}
		if forwardingConfig.Limits == (portforward.ManagerLimits{}) {
			forwardingConfig.Limits = portforward.DefaultManagerLimits()
		}
		if forwardingConfig.TrustChecker == nil {
			forwardingConfig.TrustChecker = devices
		}
		if forwardingConfig.RouterTrustChecker == nil {
			routerTrust, trustErr := meshnet.OpenRouteSourceRoutersTrust(stateDir)
			if trustErr != nil {
				_ = connectionService.Close()
				return nil, fmt.Errorf("core process: open route-router trust for forwarding: %w", trustErr)
			}
			forwardingConfig.RouterTrustChecker = routerTrust
		}
		forwardingConfig.Verifier = forwardingVerifier
		forwardingConfig.ReplayPath = ""
		forwardingConfig.AllowFileReplay = false
		if forwardingConfig.Audit == nil {
			forwardingAudit, auditErr := audit.Open(stateDir)
			if auditErr != nil {
				_ = connectionService.Close()
				return nil, fmt.Errorf("core process: open forwarding audit log: %w", auditErr)
			}
			forwardingConfig.Audit = forwardingAudit
		}
		forwardingManager, err = portforward.NewManager(forwardingConfig)
		if err != nil {
			_ = connectionService.Close()
			return nil, fmt.Errorf("core process: compose port forwarding manager: %w", err)
		}
	}

	var forwardingService *coreapi.PortForwardService
	if forwardingManager != nil {
		forwardingService, err = coreapi.NewPortForwardService(forwardingManager)
		if err != nil {
			_ = forwardingManager.Close()
			_ = connectionService.Close()
			return nil, fmt.Errorf("core process: compose port forwarding service: %w", err)
		}
	}

	fileTransferService, err := coreapi.NewFileTransferService(coreapi.FileTransferServiceConfig{
		Connections: connectionService,
	})
	if err != nil {
		if forwardingManager != nil {
			_ = forwardingManager.Close()
		}
		_ = connectionService.Close()
		return nil, fmt.Errorf("core process: compose file transfer service: %w", err)
	}
	idempotentConnections, err := coreapi.NewConnectIdempotencyService(connectionService)
	if err != nil {
		if forwardingManager != nil {
			_ = forwardingManager.Close()
		}
		_ = connectionService.Close()
		return nil, fmt.Errorf("core process: compose connect idempotency service: %w", err)
	}
	idempotentTerminal, err := coreapi.NewTerminalWriteIdempotencyService(connectionService)
	if err != nil {
		if forwardingManager != nil {
			_ = forwardingManager.Close()
		}
		_ = connectionService.Close()
		return nil, fmt.Errorf("core process: compose terminal write idempotency service: %w", err)
	}

	server, err := ipc.NewServerWithServices(ipc.Services{
		Status:         readService,
		Devices:        readService,
		Account:        accountService,
		Connections:    idempotentConnections,
		Terminal:       idempotentTerminal,
		FileTransfer:   fileTransferService,
		Transports:     networkService,
		Routes:         networkService,
		Router:         cfg.RouterService,
		PortForwarding: forwardingService,
	})
	if err != nil {
		if forwardingManager != nil {
			_ = forwardingManager.Close()
		}
		_ = connectionService.Close()
		return nil, fmt.Errorf("core process: compose IPC server: %w", err)
	}
	return &Runtime{Server: server, Connections: connectionService, Forwarding: forwardingManager, PortForwarding: forwardingService}, nil
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

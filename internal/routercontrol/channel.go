package routercontrol

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/meshruntime"
	"wedecent.com/wedecent/internal/trust"
)

const ControllerTrustFile = "trusted-router-controllers.json"

// RawDialFunc opens one machine-local stream to the wd-agent router-control
// endpoint. Authentication and authorization are added by NewAuthenticatedClient.
type RawDialFunc func(context.Context) (net.Conn, error)

func controllerTrustPath(stateDir string) (string, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return "", ErrAuthConfig
	}
	return filepath.Join(stateDir, ControllerTrustFile), nil
}

// OpenControllerTrust opens the dedicated mutable router-administration trust
// domain used by provisioning tools. It must never be replaced with terminal or
// routed-session trust stores.
func OpenControllerTrust(stateDir string) (*trust.Store, error) {
	path, err := controllerTrustPath(stateDir)
	if err != nil {
		return nil, err
	}
	store, err := trust.Open(path)
	if err != nil {
		return nil, fmt.Errorf("routercontrol: open controller trust: %w", err)
	}
	return store, nil
}

// FileControllerTrust reloads controller authorization from disk for every new
// administrative TLS connection. That makes trust additions and revocations
// effective without restarting wd-agent while still failing closed on read or
// parse errors.
type FileControllerTrust struct {
	path string
}

func NewFileControllerTrust(stateDir string) (*FileControllerTrust, error) {
	path, err := controllerTrustPath(stateDir)
	if err != nil {
		return nil, err
	}
	if _, err := trust.Open(path); err != nil {
		return nil, fmt.Errorf("routercontrol: validate controller trust: %w", err)
	}
	return &FileControllerTrust{path: path}, nil
}

func (s *FileControllerTrust) Get(id string) (trust.Peer, bool) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return trust.Peer{}, false
	}
	store, err := trust.Open(s.path)
	if err != nil {
		return trust.Peer{}, false
	}
	return store.Get(id)
}

// NewAuthenticatedClient builds the Local Core side of the router service. The
// raw dialer supplies locality; mutual TLS supplies cryptographic identity and
// authorization independent of platform socket ACLs.
func NewAuthenticatedClient(
	rawDial RawDialFunc,
	controller *identity.Identity,
	agent trust.Peer,
) (*Client, error) {
	if rawDial == nil || !validIdentity(controller) || strings.TrimSpace(agent.ID) == "" {
		return nil, ErrAuthConfig
	}
	if _, err := identity.ParseFingerprint(agent.Fingerprint); err != nil {
		return nil, ErrAuthConfig
	}

	return &Client{
		Dial: func(ctx context.Context) (net.Conn, error) {
			raw, err := rawDial(ctx)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, ctxErr
				}
				return nil, fmt.Errorf("routercontrol: open local stream: %w", err)
			}
			return DialAuthenticated(ctx, raw, controller, agent)
		},
	}, nil
}

// RuntimeServer is the wd-agent side of the router administration boundary. It
// wraps the exact meshruntime.Runtime that enforces forwarding and owns no
// listener itself.
type RuntimeServer struct {
	agent       *identity.Identity
	controllers ControllerTrust
	protocol    *ProtocolServer
}

func NewRuntimeServer(
	runtime *meshruntime.Runtime,
	controllers ControllerTrust,
) (*RuntimeServer, error) {
	if runtime == nil || runtime.Identity == nil || controllers == nil {
		return nil, coreapi.ErrRouterUnavailable
	}
	service, err := NewRuntimeService(runtime)
	if err != nil {
		return nil, err
	}

	var exposed v1.RouterService = service
	if fileTrust, ok := controllers.(*FileControllerTrust); ok && fileTrust != nil {
		auditLog, auditErr := audit.Open(filepath.Dir(fileTrust.path))
		if auditErr != nil {
			return nil, fmt.Errorf("routercontrol: open audit log: %w", auditErr)
		}
		exposed = newAuditedRouterService(service, auditLog, runtime.Identity.ID)
	}

	return &RuntimeServer{
		agent:       runtime.Identity,
		controllers: controllers,
		protocol:    &ProtocolServer{Service: exposed},
	}, nil
}

// ServeOne authenticates one already-accepted local stream and handles one
// bounded router-control request. Ownership of raw transfers to this method.
func (s *RuntimeServer) ServeOne(ctx context.Context, raw net.Conn) error {
	if raw == nil {
		return ErrAuthConfig
	}
	if s == nil || s.agent == nil || s.controllers == nil || s.protocol == nil {
		_ = raw.Close()
		return coreapi.ErrRouterUnavailable
	}

	conn, err := AcceptAuthenticated(ctx, raw, s.agent, s.controllers)
	if err != nil {
		return err
	}
	defer conn.Close()

	requestCtx, cancel := context.WithTimeout(ctx, controlIOTimeout)
	defer cancel()
	deadline, _ := requestCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	requestCtx = withRouterAuditActor(requestCtx, authenticatedControllerID(conn))

	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(requestCtx, func() {
		defer close(closeDone)
		_ = conn.Close()
	})

	err = s.protocol.ServeOne(requestCtx, conn)
	if !stopClose() {
		<-closeDone
	}
	if ctxErr := requestCtx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("routercontrol: serve request: %w", err)
	}
	return nil
}

func authenticatedControllerID(conn net.Conn) string {
	stateConn, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		return ""
	}
	cert, err := identity.PeerCertificate(stateConn.ConnectionState())
	if err != nil {
		return ""
	}
	return identity.CertificateDeviceID(cert)
}

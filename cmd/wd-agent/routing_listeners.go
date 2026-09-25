package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/meshruntime"
	"wedecent.com/wedecent/internal/routercontrol"
	"wedecent.com/wedecent/internal/session"
	"wedecent.com/wedecent/internal/transport"
)

const (
	defaultRouteMaxConnections      = 16
	defaultRouteAdminMaxConnections = 8
	defaultRouteLANDiscoveryTimeout = 3 * time.Second

	listenerRoleDirect       = "direct-terminal"
	listenerRoleRFCOMM       = "rfcomm-terminal"
	listenerRoleRouteControl = "route-control"
	listenerRoleRouteTunnel  = "route-tunnel"
	listenerRoleRouterAdmin  = "router-admin"
)

var errAgentRoutingConfig = errors.New(
	"wd-agent: invalid routing listener configuration",
)

var listenRFCOMM = transport.ListenRFCOMM

type agentRoutingRuntime struct {
	runtime          *meshruntime.Runtime
	controlTransport mesh.TransportName
	tunnelTransport  mesh.TransportName
}

func routingRequested(cfg serveConfig) bool {
	return strings.TrimSpace(cfg.RouteControlListenAddr) != "" ||
		strings.TrimSpace(cfg.RouteTunnelListenAddr) != ""
}

func parseRoutingTransport(raw string) (mesh.TransportName, error) {
	transport := mesh.TransportName(
		strings.ToLower(strings.TrimSpace(raw)),
	)

	switch transport {
	case mesh.TransportLAN, mesh.TransportInternet:
		return transport, nil
	default:
		return "", fmt.Errorf(
			"%w: routing transport must be %q or %q",
			errAgentRoutingConfig,
			mesh.TransportLAN,
			mesh.TransportInternet,
		)
	}
}

func openAgentRoutingRuntime(
	cfg serveConfig,
	id *identity.Identity,
	handler meshnet.EndpointConnHandler,
) (*agentRoutingRuntime, error) {
	if !routingRequested(cfg) {
		return nil, nil
	}

	if cfg.RouteMaxConnections < 1 ||
		cfg.RouteMaxConnections > 1024 {
		return nil, fmt.Errorf(
			"%w: route max connections out of range",
			errAgentRoutingConfig,
		)
	}

	controlTransport := mesh.TransportInternet
	if strings.TrimSpace(cfg.RouteControlListenAddr) != "" {
		parsed, err := parseRoutingTransport(
			cfg.RouteControlTransport,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: route-control transport: %v",
				errAgentRoutingConfig,
				err,
			)
		}
		controlTransport = parsed
	}

	tunnelTransport := mesh.TransportInternet
	if strings.TrimSpace(cfg.RouteTunnelListenAddr) != "" {
		parsed, err := parseRoutingTransport(
			cfg.RouteTunnelTransport,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: route-tunnel transport: %v",
				errAgentRoutingConfig,
				err,
			)
		}
		tunnelTransport = parsed
	}

	policy := mesh.DisabledRouterPolicy()

	// A route-control listener is explicit router opt-in.
	// A route-tunnel-only node remains a destination, not a router.
	if strings.TrimSpace(cfg.RouteControlListenAddr) != "" {
		policy = mesh.RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
			MaxSessions:        cfg.RouteMaxConnections,
		}
	}

	runtime, err := meshruntime.Open(meshruntime.Config{
		StateDir:             cfg.StateDir,
		Identity:             id,
		EndpointHandler:      handler,
		RouterPolicy:         policy,
		DestinationTransport: tunnelTransport,
		LANDiscoveryTimeout:  defaultRouteLANDiscoveryTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"wd-agent: configure mesh routing runtime: %w",
			err,
		)
	}

	return &agentRoutingRuntime{
		runtime:          runtime,
		controlTransport: controlTransport,
		tunnelTransport:  tunnelTransport,
	}, nil
}

type agentListener struct {
	role           string
	listener       net.Listener
	maxConnections int
	handler        func(context.Context, net.Conn) error
}

type agentListenerSet struct {
	listeners []agentListener
	direct    net.Listener
}

func openAgentListeners(
	cfg serveConfig,
	server *session.Server,
	routing *agentRoutingRuntime,
) (*agentListenerSet, error) {
	if server == nil {
		return nil, errors.New(
			"wd-agent: endpoint session server is unavailable",
		)
	}

	if routingRequested(cfg) && routing == nil {
		return nil, errAgentRoutingConfig
	}

	set := &agentListenerSet{}

	addListener := func(
		role string,
		listener net.Listener,
		maxConnections int,
		handler func(context.Context, net.Conn) error,
	) error {
		if listener == nil {
			return errors.New("wd-agent: listener is unavailable")
		}
		if maxConnections < 1 {
			_ = listener.Close()
			return fmt.Errorf(
				"%w: %s connection limit is invalid",
				errAgentRoutingConfig,
				role,
			)
		}
		set.listeners = append(set.listeners, agentListener{
			role:           role,
			listener:       listener,
			maxConnections: maxConnections,
			handler:        handler,
		})
		return nil
	}

	addTCP := func(
		role string,
		address string,
		maxConnections int,
		handler func(context.Context, net.Conn) error,
	) (net.Listener, error) {
		if address == "" {
			return nil, nil
		}
		if maxConnections < 1 {
			return nil, fmt.Errorf(
				"%w: %s connection limit is invalid",
				errAgentRoutingConfig,
				role,
			)
		}

		listener, err := net.Listen("tcp", address)
		if err != nil {
			return nil, fmt.Errorf(
				"wd-agent: listen %s on %s: %w",
				role,
				address,
				err,
			)
		}
		if err := addListener(role, listener, maxConnections, handler); err != nil {
			return nil, err
		}
		return listener, nil
	}

	direct, err := addTCP(
		listenerRoleDirect,
		cfg.ListenAddr,
		cfg.MaxConnections,
		func(_ context.Context, conn net.Conn) error {
			server.ServeConn(conn)
			return nil
		},
	)
	if err != nil {
		set.close()
		return nil, err
	}
	set.direct = direct

	if cfg.RFCOMMChannel != 0 {
		rfcomm, err := listenRFCOMM(cfg.RFCOMMChannel)
		if err != nil {
			set.close()
			return nil, fmt.Errorf(
				"wd-agent: listen %s on channel %d: %w",
				listenerRoleRFCOMM,
				cfg.RFCOMMChannel,
				err,
			)
		}
		if err := addListener(
			listenerRoleRFCOMM,
			rfcomm,
			cfg.MaxConnections,
			func(_ context.Context, conn net.Conn) error {
				server.ServeConn(conn)
				return nil
			},
		); err != nil {
			set.close()
			return nil, err
		}
	}

	if strings.TrimSpace(cfg.RouteControlListenAddr) != "" {
		_, err = addTCP(
			listenerRoleRouteControl,
			cfg.RouteControlListenAddr,
			cfg.RouteMaxConnections,
			func(ctx context.Context, conn net.Conn) error {
				_, err := routing.runtime.ServeRouteControl(
					ctx,
					conn,
					routing.controlTransport,
				)
				return err
			},
		)
		if err != nil {
			set.close()
			return nil, err
		}

		// Windows named pipes and Linux abstract Unix sockets provide a
		// machine-local byte stream across the agent/service-user boundary.
		// Bind the admin endpoint only on platforms with an implemented local
		// transport. Endpoint access is not authorization: mTLS and the dedicated
		// controller trust source still gate every router-admin request. The trust
		// source reloads its file for each new connection so revoke takes effect
		// without recycling the routing runtime.
		if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
			controllers, err := routercontrol.NewFileControllerTrust(cfg.StateDir)
			if err != nil {
				set.close()
				return nil, err
			}
			adminServer, err := routercontrol.NewRuntimeServer(routing.runtime, controllers)
			if err != nil {
				set.close()
				return nil, err
			}
			adminListener, err := routercontrol.ListenLocal()
			if err != nil {
				set.close()
				return nil, err
			}
			if err := addListener(
				listenerRoleRouterAdmin,
				adminListener,
				defaultRouteAdminMaxConnections,
				adminServer.ServeOne,
			); err != nil {
				set.close()
				return nil, err
			}
		}
	}

	if strings.TrimSpace(cfg.RouteTunnelListenAddr) != "" {
		_, err = addTCP(
			listenerRoleRouteTunnel,
			cfg.RouteTunnelListenAddr,
			cfg.RouteMaxConnections,
			func(ctx context.Context, conn net.Conn) error {
				return routing.runtime.ServeRouteTunnel(ctx, conn)
			},
		)
		if err != nil {
			set.close()
			return nil, err
		}
	}

	return set, nil
}

func (s *agentListenerSet) printAddresses() {
	if s == nil {
		return
	}

	for _, listener := range s.listeners {
		switch listener.role {
		case listenerRoleDirect:
			fmt.Printf(
				"Listening:     %s\n",
				listener.listener.Addr(),
			)

		case listenerRoleRFCOMM:
			fmt.Printf(
				"RFCOMM:        %s\n",
				listener.listener.Addr(),
			)

		case listenerRoleRouteControl:
			fmt.Printf(
				"Route control: %s\n",
				listener.listener.Addr(),
			)

		case listenerRoleRouteTunnel:
			fmt.Printf(
				"Route tunnel:  %s\n",
				listener.listener.Addr(),
			)

		case listenerRoleRouterAdmin:
			fmt.Printf(
				"Router admin:  %s\n",
				listener.listener.Addr(),
			)
		}
	}
}

func (s *agentListenerSet) serve(ctx context.Context) error {
	if s == nil || len(s.listeners) == 0 {
		<-ctx.Done()
		return nil
	}

	listenerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, len(s.listeners))

	for _, listener := range s.listeners {
		listener := listener

		go func() {
			errCh <- serveAgentListener(
				listenerCtx,
				listener,
			)
		}()
	}

	firstErr := <-errCh

	// A fatal accept error on any configured listener shuts down all listener
	// roles instead of silently leaving the process partially available. Wait
	// for every accept loop to observe shutdown before returning so callers can
	// safely rebind singleton local endpoints immediately after serve returns.
	cancel()
	s.close()
	for remaining := 1; remaining < len(s.listeners); remaining++ {
		<-errCh
	}

	if ctx.Err() != nil {
		return nil
	}

	if firstErr == nil {
		return errors.New(
			"wd-agent: listener stopped unexpectedly",
		)
	}

	return firstErr
}

func serveAgentListener(
	ctx context.Context,
	spec agentListener,
) error {
	stopContextClose := context.AfterFunc(ctx, func() {
		_ = spec.listener.Close()
	})
	defer stopContextClose()

	sem := make(chan struct{}, spec.maxConnections)

	for {
		conn, err := spec.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf(
				"wd-agent: %s listener accept: %w",
				spec.role,
				err,
			)
		}

		remote := conn.RemoteAddr().String()

		select {
		case sem <- struct{}{}:
			go func(conn net.Conn, remote string) {
				defer func() { <-sem }()
				defer conn.Close()

				if err := spec.handler(ctx, conn); err != nil &&
					ctx.Err() == nil {
					// Keep routing/session errors nonsensitive. The protocol
					// layers already collapse externally visible failures.
					slog.Warn(
						"connection ended with routing error",
						"role",
						spec.role,
						"remote",
						remote,
					)
				}
			}(conn, remote)

		default:
			_ = conn.Close()
			slog.Warn(
				"connection limit reached",
				"role",
				spec.role,
				"remote",
				remote,
			)
		}
	}
}

func (s *agentListenerSet) close() {
	if s == nil {
		return
	}

	for _, listener := range s.listeners {
		_ = listener.listener.Close()
	}
}

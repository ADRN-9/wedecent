package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshstate"
	"wedecent.com/wedecent/internal/session"
)

func TestParseServeConfigRoutingDisabledByDefault(
	t *testing.T,
) {
	t.Parallel()

	cfg, err := parseServeConfig(nil)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ListenAddr != "127.0.0.1:7443" {
		t.Fatalf(
			"default terminal listen = %q",
			cfg.ListenAddr,
		)
	}

	if cfg.RouteControlListenAddr != "" ||
		cfg.RouteTunnelListenAddr != "" {
		t.Fatal("routing listeners unexpectedly enabled by default")
	}

	if routingRequested(cfg) {
		t.Fatal("routing unexpectedly requested by default")
	}
}

func TestParseServeConfigAllowsRouteControlOnly(
	t *testing.T,
) {
	t.Parallel()

	cfg, err := parseServeConfig([]string{
		"--listen=",
		"--route-control-listen=127.0.0.1:0",
		"--route-control-transport=LAN",
	})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.RouteControlListenAddr != "127.0.0.1:0" {
		t.Fatalf(
			"route-control listen = %q",
			cfg.RouteControlListenAddr,
		)
	}

	if cfg.RouteControlTransport != string(mesh.TransportLAN) {
		t.Fatalf(
			"route-control transport = %q",
			cfg.RouteControlTransport,
		)
	}

	if !routingRequested(cfg) {
		t.Fatal("route-control listener did not enable routing")
	}
}

func TestParseServeConfigAllowsRouteTunnelOnly(
	t *testing.T,
) {
	t.Parallel()

	cfg, err := parseServeConfig([]string{
		"--listen=",
		"--route-tunnel-listen=127.0.0.1:0",
		"--route-tunnel-transport=internet",
	})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.RouteTunnelListenAddr != "127.0.0.1:0" {
		t.Fatalf(
			"route-tunnel listen = %q",
			cfg.RouteTunnelListenAddr,
		)
	}

	if !routingRequested(cfg) {
		t.Fatal("route-tunnel listener did not enable routing")
	}
}

func TestParseServeConfigRejectsUnsupportedRoutingTransport(
	t *testing.T,
) {
	t.Parallel()

	_, err := parseServeConfig([]string{
		"--route-control-transport=bluetooth",
	})
	if err == nil {
		t.Fatal("unsupported routing transport was accepted")
	}
}

func TestParseServeConfigRejectsRouteConnectionLimit(
	t *testing.T,
) {
	t.Parallel()

	_, err := parseServeConfig([]string{
		"--route-max-connections=0",
	})
	if err == nil {
		t.Fatal("zero routing connection limit was accepted")
	}
}

func TestOpenAgentRoutingRuntimeDoesNotLoadStateWhenDisabled(
	t *testing.T,
) {
	t.Parallel()

	runtime, err := openAgentRoutingRuntime(
		serveConfig{StateDir: t.TempDir()},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if runtime != nil {
		t.Fatal("routing runtime opened while routing was disabled")
	}
}

func TestOpenAgentRoutingRuntimeFailsClosedWithoutAuthority(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()

	id, err := identity.Ensure(stateDir, "router")
	if err != nil {
		t.Fatal(err)
	}

	server := &session.Server{
		Identity: id,
	}

	_, err = openAgentRoutingRuntime(
		serveConfig{
			StateDir:               stateDir,
			RouteControlListenAddr: "127.0.0.1:0",
			RouteControlTransport:  "internet",
			RouteMaxConnections:    1,
		},
		id,
		server,
	)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"routing startup error = %v, want missing authority",
			err,
		)
	}
}

func TestOpenAgentListenersBindsSeparateRoutingSockets(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()

	id, err := identity.Ensure(stateDir, "hybrid")
	if err != nil {
		t.Fatal(err)
	}

	writeTestRouteAuthority(t, stateDir)

	server := &session.Server{
		Identity: id,
	}

	cfg := serveConfig{
		StateDir:               stateDir,
		ListenAddr:             "127.0.0.1:0",
		MaxConnections:         2,
		RouteControlListenAddr: "127.0.0.1:0",
		RouteControlTransport:  "internet",
		RouteTunnelListenAddr:  "127.0.0.1:0",
		RouteTunnelTransport:   "internet",
		RouteMaxConnections:    2,
	}

	routing, err := openAgentRoutingRuntime(
		cfg,
		id,
		server,
	)
	if err != nil {
		t.Fatal(err)
	}

	listeners, err := openAgentListeners(
		cfg,
		server,
		routing,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listeners.close()

	wantListenerCount := 3
	wantRoles := []string{
		listenerRoleDirect,
		listenerRoleRouteControl,
		listenerRoleRouteTunnel,
	}
	if runtime.GOOS == "windows" {
		wantListenerCount++
		wantRoles = append(wantRoles, listenerRoleRouterAdmin)
	}
	if len(listeners.listeners) != wantListenerCount {
		t.Fatalf(
			"listener count = %d, want %d",
			len(listeners.listeners),
			wantListenerCount,
		)
	}

	if listeners.direct == nil {
		t.Fatal("direct terminal listener is nil")
	}

	seen := map[string]bool{}
	roles := map[string]bool{}

	for _, listener := range listeners.listeners {
		addr := listener.listener.Addr().String()

		if seen[addr] {
			t.Fatalf(
				"listener address reused across protocol roles: %s",
				addr,
			)
		}
		seen[addr] = true
		roles[listener.role] = true
	}

	for _, role := range wantRoles {
		if !roles[role] {
			t.Fatalf("missing listener role %q", role)
		}
	}
}

func TestAgentListenerSetStopsOnCancellation(
	t *testing.T,
) {
	t.Parallel()

	cfg := serveConfig{
		ListenAddr:     "127.0.0.1:0",
		MaxConnections: 1,
	}

	listeners, err := openAgentListeners(
		cfg,
		&session.Server{},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listeners.close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := listeners.serve(ctx); err != nil {
		t.Fatalf(
			"serve after cancellation = %v, want nil",
			err,
		)
	}
}

func writeTestRouteAuthority(
	t *testing.T,
	stateDir string,
) {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	path, err := meshstate.RouteAuthorizationAuthorityPath(
		stateDir,
	)
	if err != nil {
		t.Fatal(err)
	}

	content := fmt.Sprintf(
		"{\n"+
			"  \"version\": 1,\n"+
			"  \"key_id\": \"listener-test-key\",\n"+
			"  \"public_key\": %q\n"+
			"}\n",
		base64.RawURLEncoding.EncodeToString(publicKey),
	)

	if err := os.WriteFile(
		path,
		[]byte(content),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

// Keep net imported here as a compile-time assertion that the endpoint session
// handler used by the routing runtime remains the net.Conn structural seam.
var _ interface {
	ServeConn(net.Conn)
} = (*session.Server)(nil)

func TestOpenAgentRoutingRuntimeTunnelOnlyKeepsRouterDisabled(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()

	id, err := identity.Ensure(
		stateDir,
		"destination",
	)
	if err != nil {
		t.Fatal(err)
	}

	writeTestRouteAuthority(
		t,
		stateDir,
	)

	runtime, err := openAgentRoutingRuntime(
		serveConfig{
			StateDir:              stateDir,
			RouteTunnelListenAddr: "127.0.0.1:0",
			RouteTunnelTransport:  "internet",
			RouteMaxConnections:   2,
		},
		id,
		&session.Server{
			Identity: id,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if runtime == nil ||
		runtime.runtime == nil ||
		runtime.runtime.Router == nil {
		t.Fatal("routing runtime is incomplete")
	}

	if runtime.runtime.Router.Policy.Enabled {
		t.Fatal(
			"route-tunnel-only destination unexpectedly enabled router policy",
		)
	}
}

func TestOpenAgentRoutingRuntimeControlEnablesTrustedRouter(
	t *testing.T,
) {
	t.Parallel()

	stateDir := t.TempDir()

	id, err := identity.Ensure(
		stateDir,
		"router",
	)
	if err != nil {
		t.Fatal(err)
	}

	writeTestRouteAuthority(
		t,
		stateDir,
	)

	runtime, err := openAgentRoutingRuntime(
		serveConfig{
			StateDir:               stateDir,
			RouteControlListenAddr: "127.0.0.1:0",
			RouteControlTransport:  "internet",
			RouteMaxConnections:    7,
		},
		id,
		&session.Server{
			Identity: id,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	policy := runtime.runtime.Router.Policy

	if !policy.Enabled {
		t.Fatal(
			"route-control listener did not enable router policy",
		)
	}

	if !policy.TrustedDevicesOnly {
		t.Fatal(
			"production router is not trusted-device-only",
		)
	}

	if policy.PublicRouting {
		t.Fatal(
			"production router unexpectedly enabled public routing",
		)
	}

	if policy.MaxSessions != 7 {
		t.Fatalf(
			"router MaxSessions = %d, want 7",
			policy.MaxSessions,
		)
	}
}

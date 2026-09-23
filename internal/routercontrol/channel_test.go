package routercontrol

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshruntime"
	"wedecent.com/wedecent/internal/trust"
)

func TestAuthenticatedRuntimeServerClient(t *testing.T) {
	t.Parallel()

	agent := routerControlTestIdentity(t, "agent")
	controller := routerControlTestIdentity(t, "controller")
	controllers := routerControllerStore(t)
	if err := controllers.Put(routerControlPeer(t, controller)); err != nil {
		t.Fatal(err)
	}

	runtime := &meshruntime.Runtime{
		Identity: agent,
		Router: &mesh.Forwarder{
			Policy: mesh.RouterPolicy{
				Enabled:            true,
				TrustedDevicesOnly: true,
				MaxSessions:        4,
			},
		},
	}
	server, err := NewRuntimeServer(runtime, controllers)
	if err != nil {
		t.Fatal(err)
	}

	serverCtx, cancelServer := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelServer()

	serveErr := make(chan error, 3)
	rawDial := func(context.Context) (net.Conn, error) {
		clientSide, serverSide := routerControlTestPipe(t)
		go func() {
			serveErr <- server.ServeOne(serverCtx, serverSide)
		}()
		return clientSide, nil
	}
	client, err := NewAuthenticatedClient(
		rawDial,
		controller,
		routerControlPeer(t, agent),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	policy, err := client.GetRouterPolicy(ctx)
	if err != nil {
		t.Fatalf("GetRouterPolicy() error: %v", err)
	}
	if !policy.Enabled || !policy.TrustedDevicesOnly || policy.MaxSessions != 4 {
		t.Fatalf("unexpected initial policy: %+v", policy)
	}

	wantPolicy := v1.RouterPolicy{
		Enabled:            false,
		TrustedDevicesOnly: true,
		MaxSessions:        2,
		LANOnly:            true,
	}
	policy, err = client.SetRouterPolicy(
		ctx,
		v1.SetRouterPolicyRequest{Policy: wantPolicy},
	)
	if err != nil {
		t.Fatalf("SetRouterPolicy() error: %v", err)
	}
	if policy != wantPolicy {
		t.Fatalf("SetRouterPolicy() = %+v, want %+v", policy, wantPolicy)
	}
	if got := runtime.Router.Snapshot().Policy; got != fromV1Policy(wantPolicy) {
		t.Fatalf("authoritative runtime policy = %+v", got)
	}

	stats, err := client.GetRouterStats(ctx)
	if err != nil {
		t.Fatalf("GetRouterStats() error: %v", err)
	}
	if stats != (v1.RouterStats{}) {
		t.Fatalf("stats = %+v, want zero", stats)
	}

	for i := 0; i < 3; i++ {
		select {
		case err := <-serveErr:
			if err != nil {
				t.Fatalf("ServeOne() error: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("authenticated server did not finish request")
		}
	}
}

func TestRuntimeServerRejectsControllerOutsideDedicatedTrust(t *testing.T) {
	t.Parallel()

	agent := routerControlTestIdentity(t, "agent")
	controller := routerControlTestIdentity(t, "controller")
	controllers := routerControllerStore(t)
	runtime := &meshruntime.Runtime{
		Identity: agent,
		Router:   &mesh.Forwarder{Policy: mesh.DisabledRouterPolicy()},
	}
	server, err := NewRuntimeServer(runtime, controllers)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	rawDial := func(context.Context) (net.Conn, error) {
		clientSide, serverSide := routerControlTestPipe(t)
		go func() {
			serverErr <- server.ServeOne(ctx, serverSide)
		}()
		return clientSide, nil
	}
	client, err := NewAuthenticatedClient(
		rawDial,
		controller,
		routerControlPeer(t, agent),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = client.GetRouterPolicy(ctx)

	select {
	case err := <-serverErr:
		if !errors.Is(err, ErrControllerUntrusted) {
			t.Fatalf("ServeOne() error = %v, want ErrControllerUntrusted", err)
		}
	case <-ctx.Done():
		t.Fatal("server did not reject untrusted controller")
	}
}

func TestOpenControllerTrustUsesDedicatedStore(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	store, err := OpenControllerTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	controller := routerControlTestIdentity(t, "controller")
	peer := routerControlPeer(t, controller)
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}

	reopened, err := trust.Open(filepath.Join(stateDir, ControllerTrustFile))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get(peer.ID)
	if !ok || got.Fingerprint != peer.Fingerprint {
		t.Fatalf("dedicated controller trust = %+v, ok=%v", got, ok)
	}
}

func TestRuntimeServerFailsClosedWithoutAuthoritativeRuntime(t *testing.T) {
	t.Parallel()

	controllers := routerControllerStore(t)
	if _, err := NewRuntimeServer(nil, controllers); !errors.Is(err, coreapi.ErrRouterUnavailable) {
		t.Fatalf("NewRuntimeServer(nil) error = %v", err)
	}
}

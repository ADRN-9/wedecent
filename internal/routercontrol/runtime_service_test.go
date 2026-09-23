package routercontrol

import (
	"context"
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshruntime"
)

func TestRuntimeServiceReadsAndUpdatesAuthoritativePolicy(t *testing.T) {
	runtime := &meshruntime.Runtime{
		Router: &mesh.Forwarder{
			Policy: mesh.RouterPolicy{
				Enabled:            true,
				TrustedDevicesOnly: true,
				MaxSessions:        4,
			},
		},
	}
	service, err := NewRuntimeService(runtime)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := service.GetRouterPolicy(context.Background())
	if err != nil {
		t.Fatalf("GetRouterPolicy() error: %v", err)
	}
	if !policy.Enabled || !policy.TrustedDevicesOnly || policy.MaxSessions != 4 {
		t.Fatalf("unexpected policy: %+v", policy)
	}

	want := v1.RouterPolicy{
		Enabled:            false,
		TrustedDevicesOnly: true,
		MaxSessions:        2,
		LANOnly:            true,
	}
	got, err := service.SetRouterPolicy(
		context.Background(),
		v1.SetRouterPolicyRequest{Policy: want},
	)
	if err != nil {
		t.Fatalf("SetRouterPolicy() error: %v", err)
	}
	if got != want {
		t.Fatalf("SetRouterPolicy() = %+v, want %+v", got, want)
	}
	if runtime.Router.Snapshot().Policy != fromV1Policy(want) {
		t.Fatalf("runtime policy was not updated")
	}

	stats, err := service.GetRouterStats(context.Background())
	if err != nil {
		t.Fatalf("GetRouterStats() error: %v", err)
	}
	if stats != (v1.RouterStats{}) {
		t.Fatalf("new runtime stats = %+v, want zero", stats)
	}
}

func TestRuntimeServiceRejectsUnsupportedPolicy(t *testing.T) {
	runtime := &meshruntime.Runtime{
		Router: &mesh.Forwarder{Policy: mesh.DisabledRouterPolicy()},
	}
	service, err := NewRuntimeService(runtime)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.SetRouterPolicy(context.Background(), v1.SetRouterPolicyRequest{
		Policy: v1.RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
			PublicRouting:      true,
		},
	})
	if !errors.Is(err, coreapi.ErrInvalidRouterPolicy) {
		t.Fatalf("SetRouterPolicy() error = %v, want ErrInvalidRouterPolicy", err)
	}
	if runtime.Router.Snapshot().Policy != mesh.DisabledRouterPolicy() {
		t.Fatal("unsupported policy mutated runtime")
	}
}

func TestRuntimeServiceFailsClosedWithoutRuntime(t *testing.T) {
	if _, err := NewRuntimeService(nil); !errors.Is(err, coreapi.ErrRouterUnavailable) {
		t.Fatalf("NewRuntimeService(nil) error = %v", err)
	}

	var service *RuntimeService
	if _, err := service.GetRouterPolicy(context.Background()); !errors.Is(err, coreapi.ErrRouterUnavailable) {
		t.Fatalf("GetRouterPolicy() error = %v", err)
	}
	if _, err := service.GetRouterStats(context.Background()); !errors.Is(err, coreapi.ErrRouterUnavailable) {
		t.Fatalf("GetRouterStats() error = %v", err)
	}
	if _, err := service.SetRouterPolicy(context.Background(), v1.SetRouterPolicyRequest{}); !errors.Is(err, coreapi.ErrRouterUnavailable) {
		t.Fatalf("SetRouterPolicy() error = %v", err)
	}
}

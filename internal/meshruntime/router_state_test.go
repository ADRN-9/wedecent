package meshruntime

import (
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/mesh"
)

func TestRouterStateUsesAuthoritativeForwarderSnapshot(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	id := testIdentity(t, stateDir, "router")
	provisionAuthority(t, stateDir)

	runtime := openTestRuntime(t, stateDir, id)
	state, err := runtime.RouterState()
	if err != nil {
		t.Fatalf("RouterState() error: %v", err)
	}

	if state.Policy != testPolicy() {
		t.Fatalf("router policy = %+v, want %+v", state.Policy, testPolicy())
	}
	if state.Stats.ActiveSessions != 0 ||
		state.Stats.BytesForwarded != 0 ||
		state.Stats.SessionsForwarded != 0 {
		t.Fatalf("new runtime stats = %+v, want zero", state.Stats)
	}
}

func TestSetRouterPolicyUpdatesAuthoritativeForwarder(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	id := testIdentity(t, stateDir, "router")
	provisionAuthority(t, stateDir)
	runtime := openTestRuntime(t, stateDir, id)

	policy := mesh.RouterPolicy{
		Enabled:            false,
		TrustedDevicesOnly: true,
		MaxSessions:        2,
		LANOnly:            true,
	}
	state, err := runtime.SetRouterPolicy(policy)
	if err != nil {
		t.Fatalf("SetRouterPolicy() error: %v", err)
	}
	if state.Policy != policy {
		t.Fatalf("returned policy = %+v, want %+v", state.Policy, policy)
	}
	if got := runtime.Router.Snapshot().Policy; got != policy {
		t.Fatalf("forwarder policy = %+v, want %+v", got, policy)
	}
}

func TestSetRouterPolicyRejectsUnsupportedFieldsWithoutMutation(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	id := testIdentity(t, stateDir, "router")
	provisionAuthority(t, stateDir)
	runtime := openTestRuntime(t, stateDir, id)
	before := runtime.Router.Snapshot().Policy

	unsupported := []mesh.RouterPolicy{
		{
			Enabled:            true,
			TrustedDevicesOnly: true,
			OrganizationOnly:   true,
		},
		{
			Enabled:            true,
			TrustedDevicesOnly: true,
			PublicRouting:      true,
		},
		{
			Enabled:                 true,
			TrustedDevicesOnly:      true,
			MaxBandwidthBytesPerSec: 1024,
		},
		{
			Enabled:            true,
			TrustedDevicesOnly: true,
			AllowOnBattery:     true,
		},
		{
			Enabled:            true,
			TrustedDevicesOnly: true,
			AllowMetered:       true,
		},
	}

	for _, policy := range unsupported {
		if _, err := runtime.SetRouterPolicy(policy); !errors.Is(err, ErrUnsupportedPolicy) {
			t.Fatalf("SetRouterPolicy(%+v) error = %v, want ErrUnsupportedPolicy", policy, err)
		}
		if got := runtime.Router.Snapshot().Policy; got != before {
			t.Fatalf("unsupported policy changed forwarder: %+v", got)
		}
	}
}

func TestRouterStateFailsClosedWithoutRouter(t *testing.T) {
	t.Parallel()

	var runtime *Runtime
	_, err := runtime.RouterState()
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("RouterState() error = %v, want ErrConfig", err)
	}
	if _, err := runtime.SetRouterPolicy(mesh.DisabledRouterPolicy()); !errors.Is(err, ErrConfig) {
		t.Fatalf("SetRouterPolicy() error = %v, want ErrConfig", err)
	}
}

package meshruntime

import (
	"errors"
	"testing"
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

func TestRouterStateFailsClosedWithoutRouter(t *testing.T) {
	t.Parallel()

	var runtime *Runtime
	_, err := runtime.RouterState()
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("RouterState() error = %v, want ErrConfig", err)
	}
}

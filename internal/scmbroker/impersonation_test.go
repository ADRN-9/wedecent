package scmbroker

import (
	"errors"
	"testing"
)

func TestWithImpersonationAlwaysReverts(t *testing.T) {
	reverted := false
	authorized, err := withImpersonation(
		func() error { return nil },
		func() error { reverted = true; return nil },
		func() (bool, error) { return true, nil },
	)
	if err != nil || !authorized || !reverted {
		t.Fatalf("authorized=%v reverted=%v err=%v", authorized, reverted, err)
	}
}

func TestWithImpersonationRevertsAfterAuthorizationError(t *testing.T) {
	wantErr := errors.New("authorization failed")
	reverted := false
	authorized, err := withImpersonation(
		func() error { return nil },
		func() error { reverted = true; return nil },
		func() (bool, error) { return false, wantErr },
	)
	if authorized || !reverted || !errors.Is(err, wantErr) {
		t.Fatalf("authorized=%v reverted=%v err=%v", authorized, reverted, err)
	}
}

func TestWithImpersonationReversionFailureOverridesAuthorization(t *testing.T) {
	wantErr := errors.New("revert failed")
	authorized, err := withImpersonation(
		func() error { return nil },
		func() error { return wantErr },
		func() (bool, error) { return true, nil },
	)
	if authorized || !errors.Is(err, wantErr) {
		t.Fatalf("authorized=%v err=%v", authorized, err)
	}
}

func TestWithImpersonationDoesNotRevertIfImpersonationFails(t *testing.T) {
	wantErr := errors.New("impersonation failed")
	reverted := false
	authorized, err := withImpersonation(
		func() error { return wantErr },
		func() error { reverted = true; return nil },
		func() (bool, error) { return true, nil },
	)
	if authorized || reverted || !errors.Is(err, wantErr) {
		t.Fatalf("authorized=%v reverted=%v err=%v", authorized, reverted, err)
	}
}

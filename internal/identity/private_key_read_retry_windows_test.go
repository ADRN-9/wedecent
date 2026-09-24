//go:build windows

package identity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtectedKeyReadRetryPolicy(t *testing.T) {
	expected := make(ed25519.PrivateKey, ed25519.PrivateKeySize)

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "sharing_violation", err: windows.ERROR_SHARING_VIOLATION},
		{name: "lock_violation", err: windows.ERROR_LOCK_VIOLATION},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, scope, err := loadProtectedPrivateKeyWithRetry(func() (ed25519.PrivateKey, keyProtectionScope, error) {
				calls++
				if calls < 3 {
					return nil, 0, fmt.Errorf("transient protected key read: %w", tc.err)
				}
				return expected, keyProtectionMachine, nil
			}, 3, 0)
			if err != nil {
				t.Fatalf("loadProtectedPrivateKeyWithRetry() error: %v", err)
			}
			if calls != 3 {
				t.Fatalf("calls = %d, want 3", calls)
			}
			if scope != keyProtectionMachine || len(got) != len(expected) {
				t.Fatal("successful retry returned the wrong key result")
			}
		})
	}
}

func TestProtectedKeyReadRetryPolicyFailsFastForUnrelatedErrors(t *testing.T) {
	calls := 0
	want := errors.New("corrupt protected key")
	_, _, err := loadProtectedPrivateKeyWithRetry(func() (ed25519.PrivateKey, keyProtectionScope, error) {
		calls++
		return nil, 0, want
	}, 20, 0)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestProtectedKeyReadRetryPolicyPreservesExhaustedRaceError(t *testing.T) {
	calls := 0
	_, _, err := loadProtectedPrivateKeyWithRetry(func() (ed25519.PrivateKey, keyProtectionScope, error) {
		calls++
		return nil, 0, fmt.Errorf("read protected identity private key: %w", windows.ERROR_SHARING_VIOLATION)
	}, 3, 0)
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("error = %v, want sharing violation", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

//go:build !windows

package audit

import (
	"os"
	"testing"
)

func secureRecoveryTestDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

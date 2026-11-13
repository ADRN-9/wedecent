//go:build !windows

package session

import (
	"os"
	"testing"
)

func preparePairingSessionTestDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

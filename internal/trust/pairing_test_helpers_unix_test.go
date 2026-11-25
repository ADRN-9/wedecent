//go:build !windows

package trust

import (
	"os"
	"testing"
)

func preparePairingTestDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

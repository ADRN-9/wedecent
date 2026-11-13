//go:build !windows

package trust

import (
	"fmt"
	"os"
)

// fsync of the parent directory makes new/rotated filenames and trust-store
// replacements durable on filesystems that implement directory sync.
func syncPairingDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

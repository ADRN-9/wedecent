//go:build !windows

package audit

import (
	"fmt"
	"os"
)

func syncAuditDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open audit directory: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync audit directory: %w", err)
	}
	return nil
}

func replaceAuditArchive(source, destination string) error {
	return os.Rename(source, destination)
}

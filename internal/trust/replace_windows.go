//go:build windows

package trust

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Never remove a live trust store to work around Windows rename semantics.
// MoveFileEx with WRITE_THROUGH replaces the same-directory file or fails.
func replaceStoreFile(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("stat temporary trust store: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("temporary trust store is not a regular file")
	}
	if dst, err := os.Lstat(destination); err == nil {
		if !dst.Mode().IsRegular() {
			return errors.New("trust store destination must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

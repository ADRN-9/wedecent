//go:build windows

package trust

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Open the reparse point itself, not its target; verify the locked file still
// has the same identity on disk. Windows LockFileEx serializes processes.
func lockPairingFile(path string) (func(), error) {
	lockPath := path + ".lock"
	name, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(handle), lockPath)
	closeOnError := func(err error) (func(), error) {
		_ = f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return closeOnError(err)
	}
	onPath, err := os.Lstat(lockPath)
	if err != nil || !info.Mode().IsRegular() || onPath.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, onPath) {
		return closeOnError(errors.New("pairing lock must be a stable regular file"))
	}
	if err := secureWindowsPairingPath(lockPath); err != nil {
		return closeOnError(fmt.Errorf("pairing lock ACL: %w", err))
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return closeOnError(fmt.Errorf("exclusive pairing lock unavailable: %w", err))
	}
	onPath, err = os.Lstat(lockPath)
	if err != nil || onPath.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, onPath) {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
		return closeOnError(errors.New("pairing lock changed during acquisition"))
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
		_ = f.Close()
	}, nil
}

// Unlike the existing trust-store replacement helper, never delete the old
// file before replacement. MoveFileEx replaces within the same directory.
func replacePairingSecretFile(source, destination string) error {
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

// Windows state-directory and file ownership is enforced by the service/user
// DACL; POSIX uid ownership has no meaning on this platform.
func pairingOwnedByCurrentUser(_ os.FileInfo) bool {
	return true
}

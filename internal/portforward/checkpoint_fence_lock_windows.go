//go:build windows

package portforward

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

func openCheckpointFenceLog(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	directory := filepath.Dir(absolute)
	if err := prepareReplayDirectory(directory); err != nil {
		return nil, fmt.Errorf("secure fencing journal directory: %w", err)
	}
	name, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), absolute)
	info, err := file.Stat()
	pathInfo, pathErr := os.Lstat(absolute)
	if err != nil || pathErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		_ = file.Close()
		return nil, errors.New("fencing journal must be a stable, non-reparse regular file")
	}
	if err := setReplayFileOwner(absolute); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("set fencing journal owner: %w", err)
	}
	if err := secureReplayFile(absolute); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("verify fencing journal ACL: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func lockCheckpointFenceLog(ctx context.Context, file *os.File) (func(), error) {
	if file == nil || ctx == nil {
		return nil, ErrCheckpointFenceStore
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var overlapped windows.Overlapped
		err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
		if err == nil {
			return func() { _ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped) }, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

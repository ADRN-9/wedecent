//go:build windows

package updateinfo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

func acquireUpdateLock(ctx context.Context, statePath string) (func(), error) {
	dir := filepath.Dir(statePath)
	if err := ensurePrivateStateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, ".update-apply.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open update lock", ErrInvalidState)
	}
	fail := func(err error) (func(), error) {
		_ = file.Close()
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return fail(fmt.Errorf("%w: update lock must be a regular file", ErrInvalidState))
	}
	linked, err := os.Lstat(path)
	if err != nil || linked.Mode()&os.ModeSymlink != 0 || !linked.Mode().IsRegular() || !os.SameFile(opened, linked) {
		return fail(fmt.Errorf("%w: update lock path is not stable", ErrInvalidState))
	}

	handle := windows.Handle(file.Fd())
	var overlapped windows.Overlapped
	for {
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
		if err == nil {
			return func() {
				_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
				_ = file.Close()
			}, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return fail(fmt.Errorf("%w: acquire update lock", ErrInvalidState))
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fail(ctx.Err())
		case <-timer.C:
		}
	}
}

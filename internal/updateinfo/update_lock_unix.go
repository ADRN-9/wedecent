//go:build !windows

package updateinfo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
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
	if err := file.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("%w: protect update lock", ErrInvalidState))
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return fail(fmt.Errorf("%w: update lock must be a regular file", ErrInvalidState))
	}
	linked, err := os.Lstat(path)
	if err != nil || linked.Mode()&os.ModeSymlink != 0 || !linked.Mode().IsRegular() || !os.SameFile(opened, linked) {
		return fail(fmt.Errorf("%w: update lock path is not stable", ErrInvalidState))
	}

	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
				_ = file.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
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

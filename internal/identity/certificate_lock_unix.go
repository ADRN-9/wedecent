//go:build !windows

package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func lockIdentityCertificate(path string, exclusive bool) (func(), error) {
	lockPath := filepath.Clean(path) + ".lock"
	before, err := os.Lstat(lockPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat identity certificate lock: %w", err)
	}
	if err == nil && (before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular()) {
		return nil, errors.New("identity certificate lock must be a regular file")
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open identity certificate lock: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat opened identity certificate lock: %w", err)
	}
	after, err := os.Lstat(lockPath)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("re-stat identity certificate lock: %w", err)
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !opened.Mode().IsRegular() || !os.SameFile(opened, after) || (before != nil && !os.SameFile(before, opened)) {
		file.Close()
		return nil, errors.New("identity certificate lock path changed while opening")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure identity certificate lock permissions: %w", err)
	}
	op := syscall.LOCK_SH
	if exclusive {
		op = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(file.Fd()), op); err != nil {
		file.Close()
		return nil, fmt.Errorf("lock identity certificate: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

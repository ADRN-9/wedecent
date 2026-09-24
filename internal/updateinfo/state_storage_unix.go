//go:build !windows

package updateinfo

import (
	"fmt"
	"os"
	"syscall"
)

func validateStateFileInfo(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: update state permissions are too broad: %o (want 600)", ErrInvalidState, info.Mode().Perm())
	}
	return validateEffectiveOwner(info, "update state")
}

func validateStateDirInfo(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: update state directory permissions are too broad: %o (want 700)", ErrInvalidState, info.Mode().Perm())
	}
	return validateEffectiveOwner(info, "update state directory")
}

func validateEffectiveOwner(info os.FileInfo, what string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot determine %s owner", ErrInvalidState, what)
	}
	if uint64(stat.Uid) != uint64(os.Geteuid()) {
		return fmt.Errorf("%w: %s is not owned by the effective user", ErrInvalidState, what)
	}
	return nil
}

func replaceStateFile(tmpPath, path, dir string) error {
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("%w: install update state: %v", ErrInvalidState, err)
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("%w: open update state directory: %v", ErrInvalidState, err)
	}
	defer dirFile.Close()
	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("%w: sync update state directory: %v", ErrInvalidState, err)
	}
	return nil
}

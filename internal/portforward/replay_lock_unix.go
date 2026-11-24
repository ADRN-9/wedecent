//go:build !windows

package portforward

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func setReplayFileOwner(string) error {
	return nil
}

func prepareReplayDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return secureReplayDirectory(path)
}

func secureReplayDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("replay directory must be a real directory")
	}
	if !replayOwnedByCurrentUser(info) {
		return fmt.Errorf("replay directory is not owned by the current user")
	}
	if info.Mode().Perm() != 0o700 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("replay directory permissions must be exactly 0700")
	}
	return nil
}

func secureReplayFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("replay file must be a regular file")
	}
	if !replayOwnedByCurrentUser(info) {
		return fmt.Errorf("replay file is not owned by the current user")
	}
	if info.Mode().Perm() != 0o600 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("replay file permissions must be exactly 0600")
	}
	return nil
}

func replayOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(unix.Geteuid())
}

func openReplayLockFile(lockPath string) (*os.File, bool, error) {
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	created := true
	if os.IsExist(err) {
		created = false
		file, err = os.OpenFile(lockPath, os.O_RDWR, 0o600)
	}
	if err != nil {
		return nil, false, err
	}
	return file, created, nil
}

func lockReplayFileOS(path string) (func() error, bool, error) {
	dir := filepath.Dir(path)
	if err := secureReplayDirectory(dir); err != nil {
		return nil, false, err
	}
	lockPath := path + ".lock"
	_, anchorErr := os.Lstat(path + ".anchor")
	_, stateErr := os.Lstat(path)
	_, lockErr := os.Lstat(lockPath)
	lockMissing := os.IsNotExist(lockErr)
	if lockMissing && (!os.IsNotExist(anchorErr) || !os.IsNotExist(stateErr)) {
		return nil, false, fmt.Errorf("replay lock was deleted after initialization")
	}
	if lockErr == nil {
		if err := secureReplayFile(lockPath); err != nil {
			return nil, false, err
		}
	} else if !lockMissing {
		return nil, false, lockErr
	}

	file, created, err := openReplayLockFile(lockPath)
	if err != nil {
		return nil, false, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, false, errors.Join(err, file.Close())
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return nil, false, errors.Join(fmt.Errorf("replay lock changed during open"), file.Close())
	}
	if err := secureReplayFile(lockPath); err != nil {
		return nil, false, errors.Join(err, file.Close())
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return nil, false, errors.Join(fmt.Errorf("lock replay store: %w", err), file.Close())
	}
	return func() error {
		return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
	}, created, nil
}

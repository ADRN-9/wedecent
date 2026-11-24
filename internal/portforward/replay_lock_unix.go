//go:build !windows

package portforward

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

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

func replayPathExistsForLock(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func openReplayLockAnchor(path, statePath string) (*os.File, bool, error) {
	lockPath := path + ".lock"
	anchorPath := lockPath + ".anchor"
	anchorExists, err := replayPathExistsForLock(anchorPath)
	if err != nil {
		return nil, false, err
	}
	lockExists, err := replayPathExistsForLock(lockPath)
	if err != nil {
		return nil, false, err
	}
	initialized := false
	for _, candidate := range []string{
		statePath, statePath + ".anchor", statePath + ".init", statePath + ".pending",
		path, path + ".anchor", path + ".init", path + ".pending",
	} {
		exists, checkErr := replayPathExistsForLock(candidate)
		if checkErr != nil {
			return nil, false, checkErr
		}
		initialized = initialized || exists
	}
	if !anchorExists && !lockExists && initialized {
		return nil, false, errors.New("persistent replay lock anchor is missing after initialization")
	}

	var file *os.File
	created := false
	if anchorExists {
		file, err = os.OpenFile(anchorPath, os.O_RDWR, 0o600)
	} else if lockExists {
		// Adopt the pre-anchor lock inode in place; never replace a live lock.
		file, err = os.OpenFile(lockPath, os.O_RDWR, 0o600)
		if err == nil {
			if err = secureReplayFile(lockPath); err == nil {
				err = os.Link(lockPath, anchorPath)
				if errors.Is(err, os.ErrExist) {
					err = nil
				}
			}
		}
	} else {
		file, err = os.OpenFile(anchorPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			created = true
		} else if errors.Is(err, os.ErrExist) {
			file, err = os.OpenFile(anchorPath, os.O_RDWR, 0o600)
		}
	}
	if err != nil {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		return nil, false, err
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, false, errors.Join(err, file.Close())
		}
	}
	if err := secureReplayFile(anchorPath); err != nil {
		return nil, false, errors.Join(err, file.Close())
	}
	if created {
		if err := file.Sync(); err != nil {
			return nil, false, errors.Join(err, file.Close())
		}
		if err := syncReplayDirectory(filepath.Dir(anchorPath)); err != nil {
			return nil, false, errors.Join(err, file.Close())
		}
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, false, errors.Join(err, file.Close())
	}
	anchorInfo, err := os.Lstat(anchorPath)
	if err != nil || anchorInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, anchorInfo) {
		return nil, false, errors.Join(errors.New("persistent replay lock anchor changed during open"), file.Close())
	}

	if lockExists {
		if err := secureReplayFile(lockPath); err != nil {
			return nil, false, errors.Join(err, file.Close())
		}
		lockInfo, err := os.Lstat(lockPath)
		if err != nil || !os.SameFile(openedInfo, lockInfo) {
			return nil, false, errors.Join(errors.New("replay lock path was replaced"), file.Close())
		}
	} else {
		if initialized && !created {
			return nil, false, errors.Join(errors.New("replay lock path was deleted after initialization"), file.Close())
		}
		if err := os.Link(anchorPath, lockPath); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, false, errors.Join(err, file.Close())
		}
		lockInfo, err := os.Lstat(lockPath)
		if err != nil || lockInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, lockInfo) {
			return nil, false, errors.Join(errors.New("replay lock alias changed during initialization"), file.Close())
		}
		if err := syncReplayDirectory(filepath.Dir(lockPath)); err != nil {
			return nil, false, errors.Join(err, file.Close())
		}
	}
	return file, created, nil
}

func lockReplayFileOSContext(ctx context.Context, path, statePath string, onWait func()) (func() error, bool, error) {
	if ctx == nil {
		return nil, false, errors.New("replay lock context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	dir := filepath.Dir(path)
	if err := secureReplayDirectory(dir); err != nil {
		return nil, false, err
	}
	file, created, err := openReplayLockAnchor(path, statePath)
	if err != nil {
		return nil, false, err
	}
	waitNotified := false
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, false, errors.Join(fmt.Errorf("lock replay store: %w", err), file.Close())
		}
		if !waitNotified && onWait != nil {
			onWait()
			waitNotified = true
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, false, errors.Join(ctx.Err(), file.Close())
		case <-timer.C:
		}
	}

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, false, errors.Join(err, unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
	}
	for _, lockPath := range []string{path + ".lock.anchor", path + ".lock"} {
		pathInfo, statErr := os.Lstat(lockPath)
		if statErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
			return nil, false, errors.Join(errors.New("replay lock inode changed while acquiring lock"), unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
		}
		if err := secureReplayFile(lockPath); err != nil {
			return nil, false, errors.Join(err, unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
		}
	}
	return func() error {
		return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
	}, created, nil
}

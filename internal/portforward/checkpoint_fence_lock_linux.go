//go:build linux

package portforward

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func openCheckpointFenceLog(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("fencing journal directory must be a non-symlink, non-group-writable directory")
	}
	fd, err := syscall.Open(absolute, syscall.O_CREAT|syscall.O_RDWR|syscall.O_APPEND|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), absolute)
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, errors.New("fencing journal must be a private regular file")
	}
	return file, nil
}

func lockCheckpointFenceLog(ctx context.Context, file *os.File) (func(), error) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

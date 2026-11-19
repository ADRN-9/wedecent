//go:build !windows

package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// ReadPrivateFile reads a bounded regular file without following a final
// symlink. The file must be owned by the current user and inaccessible to
// group/other users.
func ReadPrivateFile(path string, maxBytes int64) ([]byte, error) {
	if path == "" || maxBytes < 1 {
		return nil, errors.New("private file path and positive size limit are required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open private file without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open private file returned an invalid descriptor")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat private file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("private file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private file must not be accessible to group or other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("private file ownership is unavailable")
	}
	if err := validatePrivateFileOwner(stat.Uid, uint32(os.Geteuid())); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read private file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		clear(data)
		return nil, errors.New("private file exceeds size limit")
	}
	return data, nil
}

func validatePrivateFileOwner(owner, current uint32) error {
	if owner != current {
		return errors.New("private file must be owned by the current user")
	}
	return nil
}

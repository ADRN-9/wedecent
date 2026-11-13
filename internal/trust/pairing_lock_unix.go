//go:build !windows

package trust

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// The lock inode is never renamed or deleted. O_NOFOLLOW prevents a symlink
// from redirecting permission changes or the lock onto another file.
func lockPairingFile(path string) (func(), error) {
	lockPath := path + ".lock"
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), lockPath)
	closeOnError := func(err error) (func(), error) {
		_ = f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return closeOnError(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !pairingOwnedByCurrentUser(info) {
		return closeOnError(errors.New("pairing lock must be a private regular file"))
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return closeOnError(fmt.Errorf("exclusive pairing lock unavailable: %w", err))
	}
	onPath, err := os.Lstat(lockPath)
	if err != nil || onPath.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, onPath) {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return closeOnError(errors.New("pairing lock changed during acquisition"))
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

func replacePairingSecretFile(source, destination string) error {
	return os.Rename(source, destination)
}

func pairingOwnedByCurrentUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}

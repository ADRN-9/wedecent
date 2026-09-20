//go:build aix || android || darwin || dragonfly || freebsd || ios || linux || netbsd || openbsd || solaris

package localipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"wedecent.com/wedecent/internal/appdirs"
)

const unixSocketName = "core-v1.sock"

// Endpoint returns the current user's local Core API endpoint without creating
// files or directories.
func Endpoint() (string, error) {
	dir, err := appdirs.Core()
	if err != nil {
		return "", err
	}
	if dir == "" {
		return "", fmt.Errorf("%w: empty core directory", ErrUnsafeEndpoint)
	}
	return filepath.Join(dir, unixSocketName), nil
}

// Listen creates a mode-protected Unix-domain socket for the current user.
// The containing directory is owned by the effective user and mode 0700; the
// socket is mode 0600. An existing live endpoint is never replaced.
func Listen() (net.Listener, error) {
	path, err := Endpoint()
	if err != nil {
		return nil, err
	}
	if err := secureCoreDirectory(filepath.Dir(path), true); err != nil {
		return nil, err
	}
	if err := prepareUnixSocket(path); err != nil {
		return nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("core local ipc: listen: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("core local ipc: restrict socket: %w", err)
	}
	if err := verifyUnixSocket(path); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return listener, nil
}

// Dial connects to the current user's local Core API endpoint.
func Dial(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := Endpoint()
	if err != nil {
		return nil, err
	}
	if err := secureCoreDirectory(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	if err := verifyUnixSocket(path); err != nil {
		return nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("core local ipc: dial: %w", err)
	}
	return conn, nil
}

func secureCoreDirectory(dir string, create bool) error {
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("core local ipc: create directory: %w", err)
		}
	}

	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("core local ipc: inspect directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: core directory must be a real directory", ErrUnsafeEndpoint)
	}
	if !ownedByEffectiveUser(info) {
		return fmt.Errorf("%w: core directory owner mismatch", ErrUnsafeEndpoint)
	}

	if create && info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("core local ipc: restrict directory: %w", err)
		}
		info, err = os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("core local ipc: re-inspect directory: %w", err)
		}
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: core directory mode must be 0700", ErrUnsafeEndpoint)
	}
	return nil
}

func prepareUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("core local ipc: inspect endpoint: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || !ownedByEffectiveUser(info) {
		return fmt.Errorf("%w: existing endpoint is not an owned socket", ErrUnsafeEndpoint)
	}

	conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return ErrEndpointInUse
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("core local ipc: remove stale endpoint: %w", err)
	}
	return nil
}

func verifyUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("core local ipc: inspect endpoint: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: endpoint is not a Unix socket", ErrUnsafeEndpoint)
	}
	if !ownedByEffectiveUser(info) {
		return fmt.Errorf("%w: endpoint owner mismatch", ErrUnsafeEndpoint)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: endpoint mode must be 0600", ErrUnsafeEndpoint)
	}
	return nil
}

func ownedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return uint64(stat.Uid) == uint64(os.Geteuid())
}

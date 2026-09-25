//go:build !windows

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	identityPrivateKeyFile      = "identity.key"
	maxLegacyPrivateKeyFileSize = 16 << 10
)

func defaultKeyProtectionScope() keyProtectionScope {
	return keyProtectionUser
}

func loadOrCreatePrivateKey(dir string, _ keyProtectionScope) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, identityPrivateKeyFile)
	priv, err := readLegacyPrivateKeyFile(path, true)
	if err == nil {
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	_, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBytes, err := marshalLegacyPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(pemBytes)
	if err := createPrivateKeyFile(path, pemBytes); err != nil {
		if errors.Is(err, os.ErrExist) {
			return readLegacyPrivateKeyFile(path, true)
		}
		return nil, err
	}
	return priv, nil
}

func loadExistingPrivateKey(dir string) (ed25519.PrivateKey, error) {
	return readLegacyPrivateKeyFile(filepath.Join(dir, identityPrivateKeyFile), false)
}

// readLegacyPrivateKeyFile rejects an unsafe path before opening it, then
// verifies that the opened descriptor still names the same regular file. All
// subsequent permission changes and reads operate on that descriptor, so a
// path swap cannot redirect them to another file.
func readLegacyPrivateKeyFile(path string, securePermissions bool) (ed25519.PrivateKey, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat identity private key path: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("identity private key must be a regular file")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open identity private key: %w", err)
	}
	defer f.Close()

	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened identity private key: %w", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("re-stat identity private key path: %w", err)
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errors.New("identity private key path changed while opening")
	}
	if securePermissions {
		if err := f.Chmod(0o600); err != nil {
			return nil, fmt.Errorf("secure identity private key permissions: %w", err)
		}
	}

	data, err := io.ReadAll(io.LimitReader(f, maxLegacyPrivateKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read identity private key: %w", err)
	}
	defer zeroBytes(data)
	if len(data) > maxLegacyPrivateKeyFileSize {
		return nil, errors.New("identity private key file is too large")
	}
	return parseLegacyPrivateKey(data)
}

// createPrivateKeyFile writes the secret into a private same-directory
// temporary file, then publishes it with an atomic no-replace hard link.
// A concurrent creator or attacker-controlled path therefore cannot be
// truncated or followed. The temporary name is removed on every return path.
func createPrivateKeyFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity.key.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary identity private key: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	cleanup := func(cause error) error {
		_ = tmp.Close()
		return cause
	}
	if err := tmp.Chmod(0o600); err != nil {
		return cleanup(fmt.Errorf("secure temporary identity private key permissions: %w", err))
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("write temporary identity private key: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("sync temporary identity private key: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary identity private key: %w", err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		return fmt.Errorf("publish identity private key: %w", err)
	}
	return nil
}

func identityPrivateKeyPath(dir string) string {
	return filepath.Join(dir, identityPrivateKeyFile)
}

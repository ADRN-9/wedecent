//go:build !windows

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const identityPrivateKeyFile = "identity.key"

func defaultKeyProtectionScope() keyProtectionScope {
	return keyProtectionUser
}

func loadOrCreatePrivateKey(dir string, _ keyProtectionScope) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, identityPrivateKeyFile)
	data, err := os.ReadFile(path)
	if err == nil {
		priv, err := parseLegacyPrivateKey(data)
		zeroBytes(data)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("secure identity private key permissions: %w", err)
		}
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBytes, err := marshalLegacyPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(pemBytes)
	if err := writePrivateFile(path, pemBytes); err != nil {
		return nil, err
	}
	return priv, nil
}

func loadExistingPrivateKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, identityPrivateKeyFile)
	if err := requireRegularFile(path, "identity private key"); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity private key: %w", err)
	}
	defer zeroBytes(data)
	return parseLegacyPrivateKey(data)
}

func identityPrivateKeyPath(dir string) string {
	return filepath.Join(dir, identityPrivateKeyFile)
}

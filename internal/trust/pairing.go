package trust

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func RotatePairingSecret(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	path := filepath.Join(dir, "pairing-secret.sha256")
	if err := os.WriteFile(path, []byte(HashSecret(secret)+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", err
	}
	return secret, nil
}

func CheckPairingSecret(dir, secret string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, "pairing-secret.sha256"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return SecretMatches(strings.TrimSpace(string(data)), secret), nil
}

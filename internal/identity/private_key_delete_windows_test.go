//go:build windows

package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyKeyHandleDeletionDoesNotDeleteReplacementPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, legacyIdentityPrivateKeyFile)
	moved := filepath.Join(dir, "legacy-opened")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := marshalLegacyPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(pemBytes)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	f, opened, err := openLegacyKeyForDeletion(path)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.Public().(ed25519.PublicKey).Equal(priv.Public().(ed25519.PublicKey)) {
		_ = f.Close()
		t.Fatal("opened legacy key does not match test key")
	}

	if err := os.Rename(path, moved); err != nil {
		_ = f.Close()
		t.Fatalf("rename opened legacy key: %v", err)
	}
	replacement := []byte("replacement-must-survive")
	if err := os.WriteFile(path, replacement, 0o600); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := markOpenedFileForDeletion(f); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement path was removed: %v", err)
	}
	if !bytes.Equal(got, replacement) {
		t.Fatalf("replacement content = %q, want %q", got, replacement)
	}
	if _, err := os.Stat(moved); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("opened legacy key still exists after handle deletion: %v", err)
	}
}

func TestVerifyAndDeleteLegacyKeyByHandleRejectsMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, legacyIdentityPrivateKeyFile)
	_, legacy, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, protected, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := marshalLegacyPrivateKey(legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(pemBytes)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := verifyAndDeleteLegacyKeyByHandle(path, protected); err == nil {
		t.Fatal("mismatched legacy key was accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("mismatched legacy key was removed: %v", err)
	}
}

func TestVerifyAndDeleteLegacyKeyByHandleRemovesMatchingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, legacyIdentityPrivateKeyFile)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := marshalLegacyPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(pemBytes)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := verifyAndDeleteLegacyKeyByHandle(path, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("matching legacy key still exists: %v", err)
	}
}

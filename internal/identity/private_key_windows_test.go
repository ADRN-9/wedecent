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

func TestEnsureCreatesDPAPIProtectedIdentityKey(t *testing.T) {
	dir := t.TempDir()
	id, err := Ensure(dir, "windows-device")
	if err != nil {
		t.Fatal(err)
	}
	protectedPath := filepath.Join(dir, identityPrivateKeyFile)
	blob, err := os.ReadFile(protectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("PRIVATE KEY")) || bytes.Contains(blob, id.PrivateKey) {
		t.Fatal("protected identity file contains plaintext private-key material")
	}
	if _, err := os.Lstat(filepath.Join(dir, legacyIdentityPrivateKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy plaintext key still exists: %v", err)
	}
	if len(blob) <= len(dpapiIdentityKeyMagic) || blob[len(dpapiIdentityKeyMagic)] != dpapiScopeMachine {
		t.Fatal("Windows identity key is not marked machine-scoped")
	}
}

func TestEnsureDPAPIIdentityIsStable(t *testing.T) {
	dir := t.TempDir()
	first, err := Ensure(dir, "stable-device")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(identityPrivateKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Ensure(dir, "stable-device")
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(identityPrivateKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || !bytes.Equal(first.PrivateKey, second.PrivateKey) {
		t.Fatal("Ensure rotated a protected Windows identity")
	}
	if !bytes.Equal(before, after) {
		t.Fatal("Ensure rewrote an existing protected Windows identity")
	}
}

func TestEnsureMigratesLegacyWindowsKeyWithoutRotation(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyWindowsKey(t, dir, priv)
	expectedID := DeviceID(priv.Public().(ed25519.PublicKey))

	id, err := Ensure(dir, "legacy-device")
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != expectedID || !bytes.Equal(id.PrivateKey, priv) {
		t.Fatal("legacy migration changed device identity")
	}
	if _, err := os.Lstat(filepath.Join(dir, legacyIdentityPrivateKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy plaintext key was not removed: %v", err)
	}
	loaded, scope, err := loadProtectedPrivateKey(identityPrivateKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if scope != keyProtectionMachine || !bytes.Equal(loaded, priv) {
		t.Fatal("migrated protected key does not match legacy key")
	}
}

func TestEnsureCorruptProtectedWindowsKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	created, err := Ensure(dir, "corrupt-device")
	if err != nil {
		t.Fatal(err)
	}
	path := identityPrivateKeyPath(dir)
	if err := os.WriteFile(path, []byte(dpapiIdentityKeyMagic+"Mbroken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(dir, "corrupt-device"); err == nil {
		t.Fatal("Ensure replaced a corrupt protected identity instead of failing closed")
	}
	if _, err := os.Lstat(filepath.Join(dir, legacyIdentityPrivateKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext key unexpectedly created: %v", err)
	}
	if DeviceID(created.PublicKey) != created.ID {
		t.Fatal("test setup identity is inconsistent")
	}
}

func TestLoadLegacyWindowsIdentityDoesNotMigrate(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyWindowsKey(t, dir, priv)
	pub := priv.Public().(ed25519.PublicKey)
	id := DeviceID(pub)
	if _, err := issueCertificate(filepath.Join(dir, "identity.crt"), "legacy-load", id, pub, priv, false); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != id || !bytes.Equal(loaded.PrivateKey, priv) {
		t.Fatal("Load changed legacy identity material")
	}
	if _, err := os.Lstat(identityPrivateKeyPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load migrated or created a protected key: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, legacyIdentityPrivateKeyFile)); err != nil {
		t.Fatalf("Load removed legacy key: %v", err)
	}
}

func TestEnsureRejectsMismatchedProtectedAndLegacyWindowsKeys(t *testing.T) {
	dir := t.TempDir()
	if _, err := Ensure(dir, "protected-device"); err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyWindowsKey(t, dir, other)
	if _, err := Ensure(dir, "protected-device"); err == nil {
		t.Fatal("Ensure accepted mismatched protected and legacy identities")
	}
	if _, err := os.Lstat(filepath.Join(dir, legacyIdentityPrivateKeyFile)); err != nil {
		t.Fatalf("mismatched legacy key was removed: %v", err)
	}
}

func writeLegacyWindowsKey(t *testing.T, dir string, priv ed25519.PrivateKey) {
	t.Helper()
	pemBytes, err := marshalLegacyPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(pemBytes)
	if err := os.WriteFile(filepath.Join(dir, legacyIdentityPrivateKeyFile), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

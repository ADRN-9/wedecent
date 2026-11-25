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

func TestProtectExistingMigratesLegacyKeyWithoutChangingCertificate(t *testing.T) {
	dir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyWindowsKey(t, dir, privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	expectedID := DeviceID(publicKey)
	if _, err := issueCertificate(filepath.Join(dir, "identity.crt"), "legacy-device", expectedID, publicKey, privateKey, false); err != nil {
		t.Fatal(err)
	}
	certificateBefore, err := os.ReadFile(filepath.Join(dir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}

	protected, err := ProtectExisting(dir)
	if err != nil {
		t.Fatal(err)
	}
	if protected.ID != expectedID || !bytes.Equal(protected.PublicKey, publicKey) {
		t.Fatal("platform key protection changed the device identity")
	}
	certificateAfter, err := os.ReadFile(filepath.Join(dir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(certificateBefore, certificateAfter) {
		t.Fatal("platform key protection renewed or replaced the identity certificate")
	}
	loaded, scope, err := loadProtectedPrivateKey(identityPrivateKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if scope != keyProtectionMachine || !bytes.Equal(loaded, privateKey) {
		t.Fatal("legacy key was not preserved in machine-scoped DPAPI storage")
	}
	if _, err := os.Lstat(filepath.Join(dir, legacyIdentityPrivateKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy plaintext key remains after verified migration: %v", err)
	}
}

func TestProtectExistingRejectsMismatchedCertificateWithoutKeyMigration(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	if _, err := Ensure(dir, "original"); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(other, "different"); err != nil {
		t.Fatal(err)
	}
	otherCert, err := os.ReadFile(filepath.Join(other, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "identity.crt"), otherCert, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(identityPrivateKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProtectExisting(dir); err == nil {
		t.Fatal("ProtectExisting accepted mismatched certificate")
	}
	after, err := os.ReadFile(identityPrivateKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed ProtectExisting changed the private key")
	}
}

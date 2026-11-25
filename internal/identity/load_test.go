package identity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExistingIdentityWithoutReplacingMaterial(t *testing.T) {
	dir := t.TempDir()
	created, err := Ensure(dir, "test-device")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := identityPrivateKeyPath(dir)
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(filepath.Join(dir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != created.ID || loaded.Name != "test-device" {
		t.Fatalf("loaded identity = %q/%q", loaded.ID, loaded.Name)
	}

	keyAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certAfter, err := os.ReadFile(filepath.Join(dir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(keyAfter) != string(keyBefore) || string(certAfter) != string(certBefore) {
		t.Fatal("Load changed identity material")
	}
}

func TestLoadMissingIdentityDoesNotCreateFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("Load succeeded without identity files")
	}
	for _, path := range []string{identityPrivateKeyPath(dir), filepath.Join(dir, "identity.crt")} {
		_, err := os.Lstat(path)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s was created or stat failed: %v", path, err)
		}
	}
}

func TestLoadRejectsSymlinkedPrivateKey(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	if _, err := Ensure(dir, "original"); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(other, "other"); err != nil {
		t.Fatal(err)
	}
	keyPath := identityPrivateKeyPath(dir)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(identityPrivateKeyPath(other), keyPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted symlinked private key")
	}
}

func TestLoadRejectsMissingCertificateWithoutCreatingReplacement(t *testing.T) {
	dir := t.TempDir()
	if _, err := Ensure(dir, "missing-certificate"); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "identity.crt")
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted identity with missing certificate")
	}
	if _, err := os.Lstat(certPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load recreated missing certificate: %v", err)
	}
	if _, err := os.Stat(identityPrivateKeyPath(dir)); err != nil {
		t.Fatalf("Load removed existing private key: %v", err)
	}
}

func TestLoadRejectsCertificateFromDifferentIdentityWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	if _, err := Ensure(dir, "original"); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(other, "different"); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "identity.crt")
	otherCert, err := os.ReadFile(filepath.Join(other, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(identityPrivateKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, otherCert, 0o600); err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted certificate belonging to another private key")
	}
	keyAfter, err := os.ReadFile(identityPrivateKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	certAfter, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyAfter) != string(keyBefore) || string(certAfter) != string(certBefore) {
		t.Fatal("failed Load mutated identity material")
	}
}

func TestProtectExistingDoesNotRenewOrReplaceIdentityCertificate(t *testing.T) {
	dir := t.TempDir()
	created, err := Ensure(dir, "protect-existing")
	if err != nil {
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
	certificateAfter, err := os.ReadFile(filepath.Join(dir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if protected.ID != created.ID || !stringEqual(certificateBefore, certificateAfter) {
		t.Fatal("ProtectExisting changed the identity or certificate")
	}
}

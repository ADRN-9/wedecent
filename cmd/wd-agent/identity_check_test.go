package main

import (
	"os"
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/identity"
)

func TestLoadIdentityForCheckIsReadOnlyAndVerifiesKeyCertificatePair(t *testing.T) {
	stateDir := t.TempDir()
	original, err := identity.Ensure(stateDir, "migration-test")
	if err != nil {
		t.Fatal(err)
	}
	keyName := "identity.key"
	if _, err := os.Stat(filepath.Join(stateDir, "identity.key.dpapi")); err == nil {
		keyName = "identity.key.dpapi"
	}
	keyPath := filepath.Join(stateDir, keyName)
	beforeKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeCert, err := os.ReadFile(filepath.Join(stateDir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := loadIdentityForCheck(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != original.ID || !loaded.PublicKey.Equal(original.PublicKey) {
		t.Fatal("read-only identity check changed device identity")
	}
	afterKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	afterCert, err := os.ReadFile(filepath.Join(stateDir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(beforeKey) != string(afterKey) || string(beforeCert) != string(afterCert) {
		t.Fatal("identity-check modified key or certificate material")
	}

	otherDir := t.TempDir()
	if _, err := identity.Ensure(otherDir, "different-identity"); err != nil {
		t.Fatal(err)
	}
	otherCert, err := os.ReadFile(filepath.Join(otherDir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "identity.crt"), otherCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentityForCheck(stateDir); err == nil {
		t.Fatal("identity-check accepted a certificate belonging to another private key")
	}
}

func TestLoadIdentityForCheckDoesNotCreateMissingState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := loadIdentityForCheck(missing); err == nil {
		t.Fatal("identity-check accepted missing state")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("identity-check created missing state: %v", err)
	}
}

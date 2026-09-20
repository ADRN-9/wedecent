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
	keyBefore, err := os.ReadFile(filepath.Join(dir, "identity.key"))
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

	keyAfter, err := os.ReadFile(filepath.Join(dir, "identity.key"))
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
	for _, name := range []string{"identity.key", "identity.crt"} {
		_, err := os.Lstat(filepath.Join(dir, name))
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s was created or stat failed: %v", name, err)
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
	keyPath := filepath.Join(dir, "identity.key")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "identity.key"), keyPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted symlinked private key")
	}
}

//go:build windows

package identity

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadVerifiedIdentityKeyFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	want := []byte("do-not-follow")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "identity.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := readVerifiedIdentityKeyFile(link, "test identity key", 1024); err == nil {
		t.Fatal("readVerifiedIdentityKeyFile accepted symlink")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestLoadLegacyPrivateKeyRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), legacyIdentityPrivateKeyFile)
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxLegacyIdentityKeyFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadLegacyPrivateKey(path)
	if err == nil || !strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("loadLegacyPrivateKey() error = %v, want invalid-size error", err)
	}
}

func TestReadVerifiedIdentityKeyFileMissingPreservesNotExist(t *testing.T) {
	_, err := readVerifiedIdentityKeyFile(filepath.Join(t.TempDir(), "missing"), "test identity key", 1024)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readVerifiedIdentityKeyFile() error = %v, want os.ErrNotExist", err)
	}
}

func TestReadVerifiedIdentityKeyFileReadsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	want := []byte("regular-file")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readVerifiedIdentityKeyFile(path, "test identity key", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("readVerifiedIdentityKeyFile() = %q, want %q", got, want)
	}
}

//go:build !windows

package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestEnsureRejectsSymlinkedPrivateKeyWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "target")
	want := []byte("do-not-touch")
	if err := os.WriteFile(target, want, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, identityPrivateKeyPath(dir)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Ensure(dir, "test-device"); err == nil {
		t.Fatal("Ensure accepted symlinked identity private key")
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("symlink target content changed: %q", got)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("symlink target mode changed from %o to %o", before.Mode().Perm(), after.Mode().Perm())
	}
}

func TestCreatePrivateKeyFileDoesNotReplaceSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	want := []byte("sentinel")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.key")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	err := createPrivateKeyFile(path, []byte("replacement"))
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("createPrivateKeyFile() error = %v, want ErrExist", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestLoadExistingPrivateKeyRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := identityPrivateKeyPath(dir)
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxLegacyPrivateKeyFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadExistingPrivateKey(dir)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("loadExistingPrivateKey() error = %v, want oversized-file error", err)
	}
}

func TestLoadOrCreatePrivateKeyConcurrentCreatorsConverge(t *testing.T) {
	dir := t.TempDir()
	const callers = 32

	start := make(chan struct{})
	keys := make(chan []byte, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			<-start
			priv, err := loadOrCreatePrivateKey(dir, keyProtectionUser)
			if err != nil {
				errs <- err
				return
			}
			pub := priv.Public().(ed25519.PublicKey)
			keys <- append([]byte(nil), pub...)
		}()
	}
	close(start)
	wg.Wait()
	close(keys)
	close(errs)

	for err := range errs {
		t.Fatalf("loadOrCreatePrivateKey() error = %v", err)
	}
	var first []byte
	count := 0
	for key := range keys {
		count++
		if first == nil {
			first = key
			continue
		}
		if !bytes.Equal(key, first) {
			t.Fatal("concurrent creators returned different identity keys")
		}
	}
	if count != callers {
		t.Fatalf("successful callers = %d, want %d", count, callers)
	}

	matches, err := filepath.Glob(filepath.Join(dir, ".identity.key.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary private key files remain: %v", matches)
	}
}

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

func TestPublishProtectedPrivateKeyDoesNotReplaceExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, identityPrivateKeyFile)
	winner := []byte("winner")
	if err := os.WriteFile(path, winner, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := publishProtectedPrivateKey(path, []byte("loser")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("publish error = %v, want os.ErrExist", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, winner) {
		t.Fatalf("existing protected key was replaced: %q", got)
	}
	assertNoProtectedKeyTemps(t, dir)
}

func TestConcurrentProtectedKeyCreationConverges(t *testing.T) {
	dir := t.TempDir()
	const workers = 16

	start := make(chan struct{})
	type result struct {
		key ed25519.PrivateKey
		err error
	}
	results := make(chan result, workers)
	for range workers {
		go func() {
			<-start
			key, err := loadOrCreatePrivateKey(dir, keyProtectionMachine)
			results <- result{key: key, err: err}
		}()
	}
	close(start)

	var expected ed25519.PrivateKey
	for range workers {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent key creation failed: %v", result.err)
		}
		if expected == nil {
			expected = result.key
			continue
		}
		if !bytes.Equal(result.key, expected) {
			t.Fatal("concurrent key creation returned different identity keys")
		}
	}
	assertNoProtectedKeyTemps(t, dir)
}

func TestConcurrentLegacyMigrationConverges(t *testing.T) {
	dir := t.TempDir()
	_, legacy, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyWindowsKey(t, dir, legacy)

	const workers = 16
	start := make(chan struct{})
	type result struct {
		key ed25519.PrivateKey
		err error
	}
	results := make(chan result, workers)
	for range workers {
		go func() {
			<-start
			key, err := loadOrCreatePrivateKey(dir, keyProtectionMachine)
			results <- result{key: key, err: err}
		}()
	}
	close(start)

	for range workers {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent legacy migration failed: %v", result.err)
		}
		if !bytes.Equal(result.key, legacy) {
			t.Fatal("concurrent legacy migration changed identity key")
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, legacyIdentityPrivateKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy plaintext key still exists: %v", err)
	}
	assertNoProtectedKeyTemps(t, dir)
}

func assertNoProtectedKeyTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "."+identityPrivateKeyFile+".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("protected-key temp files remain: %v", matches)
	}
}

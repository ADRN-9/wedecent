package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadPairingSecretFile(t *testing.T) {
	t.Setenv("WEDECENT_PAIRING_SECRET", "")
	path := filepath.Join(t.TempDir(), "pairing.secret")
	if err := os.WriteFile(path, []byte("fresh-single-use-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPairingSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "fresh-single-use-secret-value" {
		t.Fatalf("readPairingSecret() = %q", got)
	}
}

func TestReadPairingSecretFileRejectsInsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows DACLs, not POSIX mode bits, define file access")
	}
	t.Setenv("WEDECENT_PAIRING_SECRET", "")
	path := filepath.Join(t.TempDir(), "pairing.secret")
	if err := os.WriteFile(path, []byte("fresh-single-use-secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPairingSecret(path); err == nil {
		t.Fatal("group/world-readable pairing secret was accepted")
	}
}

func TestReadPairingSecretFileRejectsEmptyFileWithoutPromptFallback(t *testing.T) {
	t.Setenv("WEDECENT_PAIRING_SECRET", "")
	path := filepath.Join(t.TempDir(), "pairing.secret")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPairingSecret(path); err == nil {
		t.Fatal("empty pairing secret file fell back to interactive input")
	}
}

func TestReadPairingSecretFileRejectsEnvironmentCombination(t *testing.T) {
	t.Setenv("WEDECENT_PAIRING_SECRET", "another-secret-value-long-enough")
	path := filepath.Join(t.TempDir(), "pairing.secret")
	if err := os.WriteFile(path, []byte("fresh-single-use-secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPairingSecret(path); err == nil {
		t.Fatal("pairing secret file was combined with environment secret")
	}
}

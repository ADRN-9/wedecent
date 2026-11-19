//go:build !windows

package securefile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadPrivateFileRejectsGroupWorldAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("private-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(path, 64); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("insecure permission error = %v", err)
	}
}

func TestReadPrivateFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(path, 64); err == nil {
		t.Fatal("FIFO was accepted as a private file")
	}
}

func TestValidatePrivateFileOwner(t *testing.T) {
	if err := validatePrivateFileOwner(1001, 1001); err != nil {
		t.Fatalf("matching owner rejected: %v", err)
	}
	if err := validatePrivateFileOwner(1002, 1001); err == nil || !strings.Contains(err.Error(), "current user") {
		t.Fatalf("mismatched owner error = %v", err)
	}
}

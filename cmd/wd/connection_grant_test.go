package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadConnectionGrantFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grant.jwt")
	if err := os.WriteFile(path, []byte("header.payload.signature\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readConnectionGrantFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "header.payload.signature" {
		t.Fatalf("got %q", got)
	}
}

func TestReadConnectionGrantFileRejectsEmbeddedWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grant.jwt")
	if err := os.WriteFile(path, []byte("header.payload.signature extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConnectionGrantFile(path); err == nil {
		t.Fatal("expected embedded whitespace to fail")
	}
}

func TestReadConnectionGrantFileRejectsInsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows DACLs, not POSIX mode bits, define file access")
	}
	path := filepath.Join(t.TempDir(), "grant.jwt")
	if err := os.WriteFile(path, []byte("header.payload.signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readConnectionGrantFile(path); err == nil {
		t.Fatal("group/world-readable grant file was accepted")
	}
}

func TestReadConnectionGrantFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "grant.jwt")
	link := filepath.Join(dir, "grant-link.jwt")
	if err := os.WriteFile(target, []byte("header.payload.signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := readConnectionGrantFile(link); err == nil {
		t.Fatal("symlink grant file was accepted")
	}
}

func TestReadConnectionGrantFileRejectsDirectory(t *testing.T) {
	if _, err := readConnectionGrantFile(t.TempDir()); err == nil {
		t.Fatal("directory was accepted as a grant file")
	}
}

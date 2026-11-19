package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("private-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPrivateFile(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "private-value" {
		t.Fatalf("ReadPrivateFile() = %q", got)
	}
	clear(got)
}

func TestReadPrivateFileRejectsDirectory(t *testing.T) {
	if _, err := ReadPrivateFile(t.TempDir(), 64); err == nil {
		t.Fatal("directory was accepted as a private file")
	}
}

func TestReadPrivateFileRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(path, 4); err == nil {
		t.Fatal("oversized private file was accepted")
	}
}

func TestReadPrivateFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("private-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := ReadPrivateFile(link, 64); err == nil {
		t.Fatal("symlink was accepted as a private file")
	}
}

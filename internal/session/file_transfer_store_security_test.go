package session

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestFileTransferStoreRejectsIntermediateSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks may require elevated privileges on Windows")
	}
	rootDir := t.TempDir()
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(rootDir, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	store, err := OpenFileTransferStore(rootDir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.OpenDownload(protocol.FileDownloadOpen{Path: "escape/secret"}); err == nil {
		t.Fatal("download escaped the configured root through an intermediate symlink")
	}
	if _, err := store.BeginUpload(protocol.FileUploadOpen{Path: "escape/new", Existing: protocol.FileExistingFail}); err == nil {
		t.Fatal("upload escaped the configured root through an intermediate symlink")
	}
}

func TestFileTransferStoreSnapshotsExpectedSizeMetadata(t *testing.T) {
	rootDir := t.TempDir()
	store, err := OpenFileTransferStore(rootDir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	expected := uint64(7)
	upload, err := store.BeginUpload(protocol.FileUploadOpen{
		Path:         "immutable",
		ExpectedSize: &expected,
		Existing:     protocol.FileExistingFail,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected = 1
	if _, err := upload.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := upload.Commit(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(rootDir, "immutable")); err != nil {
		t.Fatal(err)
	} else if string(data) != "payload" {
		t.Fatalf("published data = %q", data)
	}
}

package session

import (
	"errors"
	"io"
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

func TestFileTransferDownloadDoesNotExpandIfFileGrows(t *testing.T) {
	rootDir := t.TempDir()
	path := filepath.Join(rootDir, "grow")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileTransferStore(rootDir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	download, size, err := store.OpenDownload(protocol.FileDownloadOpen{Path: "grow"})
	if err != nil {
		t.Fatal(err)
	}
	defer download.Close()
	if size != 5 {
		t.Fatalf("size = %d", size)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("-later")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(download)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("download expanded after open: %q", data)
	}
}

func TestFileTransferDownloadReportsPostOpenTruncation(t *testing.T) {
	rootDir := t.TempDir()
	path := filepath.Join(rootDir, "shrink")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileTransferStore(rootDir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	download, _, err := store.OpenDownload(protocol.FileDownloadOpen{Path: "shrink"})
	if err != nil {
		t.Fatal(err)
	}
	defer download.Close()
	if err := os.Truncate(path, 2); err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(download)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncation error = %v", err)
	}
}

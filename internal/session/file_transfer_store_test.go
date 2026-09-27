package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestFileTransferStoreDownloadIsRootedRegularAndBounded(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootDir, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "docs", "note.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileTransferStore(rootDir, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	file, size, err := store.OpenDownload(protocol.FileDownloadOpen{Path: "docs/note.txt"})
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if size != 5 || string(data) != "hello" {
		t.Fatalf("download size=%d data=%q", size, data)
	}

	if _, _, err := store.OpenDownload(protocol.FileDownloadOpen{Path: "docs"}); err == nil {
		t.Fatal("download accepted a directory")
	}
	if err := os.WriteFile(filepath.Join(rootDir, "docs", "large.txt"), []byte("123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.OpenDownload(protocol.FileDownloadOpen{Path: "docs/large.txt"}); err == nil {
		t.Fatal("download accepted an oversized file")
	}
}

func TestFileTransferStoreRejectsRootSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks may require elevated privileges on Windows")
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := OpenFileTransferStore(link, 1024); err == nil {
		t.Fatal("accepted symbolic-link file transfer root")
	}
}

func TestFileTransferStoreRejectsFinalDownloadSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks may require elevated privileges on Windows")
	}
	rootDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootDir, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	store, err := OpenFileTransferStore(rootDir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.OpenDownload(protocol.FileDownloadOpen{Path: "linked"}); err == nil {
		t.Fatal("accepted final download symlink")
	}
}

func TestFileTransferStoreUploadStagesValidatesAndPublishesWithoutOverwrite(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootDir, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileTransferStore(rootDir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	payload := []byte("payload")
	digest := sha256.Sum256(payload)
	size := uint64(len(payload))
	upload, err := store.BeginUpload(protocol.FileUploadOpen{
		Path:         "incoming/file.bin",
		ExpectedSize: &size,
		SHA256:       hex.EncodeToString(digest[:]),
		Existing:     protocol.FileExistingFail,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := upload.Commit(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(rootDir, "incoming", "file.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payload) {
		t.Fatalf("published data = %q", data)
	}
	if matches, err := filepath.Glob(filepath.Join(rootDir, "incoming", ".wedecent-upload-*.tmp")); err != nil {
		t.Fatal(err)
	} else if len(matches) != 0 {
		t.Fatalf("staging files remain after commit: %#v", matches)
	}

	if _, err := store.BeginUpload(protocol.FileUploadOpen{Path: "incoming/file.bin", Existing: protocol.FileExistingFail}); err == nil {
		t.Fatal("accepted existing upload destination")
	}
	if _, err := store.BeginUpload(protocol.FileUploadOpen{Path: "incoming/replace.bin", Existing: protocol.FileExistingReplace}); err == nil {
		t.Fatal("accepted unimplemented replace policy")
	}
}

func TestFileTransferStoreUploadFailureAndCancelRemoveStaging(t *testing.T) {
	rootDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootDir, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileTransferStore(rootDir, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	upload, err := store.BeginUpload(protocol.FileUploadOpen{Path: "incoming/too-large", Existing: protocol.FileExistingFail})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Write([]byte("12345")); err == nil {
		t.Fatal("oversized upload write succeeded")
	}
	assertNoUploadStaging(t, rootDir, "incoming")
	if _, err := os.Stat(filepath.Join(rootDir, "incoming", "too-large")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed upload destination exists: %v", err)
	}

	upload, err = store.BeginUpload(protocol.FileUploadOpen{Path: "incoming/cancelled", Existing: protocol.FileExistingFail})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Write([]byte("12")); err != nil {
		t.Fatal(err)
	}
	if err := upload.Cancel(); err != nil {
		t.Fatal(err)
	}
	assertNoUploadStaging(t, rootDir, "incoming")
}

func TestFileTransferStoreUploadRejectsSizeAndDigestMismatch(t *testing.T) {
	rootDir := t.TempDir()
	store, err := OpenFileTransferStore(rootDir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	expected := uint64(3)
	upload, err := store.BeginUpload(protocol.FileUploadOpen{Path: "short", ExpectedSize: &expected, Existing: protocol.FileExistingFail})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Write([]byte("12")); err != nil {
		t.Fatal(err)
	}
	if err := upload.Commit(); err == nil || !strings.Contains(err.Error(), "expected size") {
		t.Fatalf("size mismatch commit error = %v", err)
	}
	assertNoUploadStaging(t, rootDir, ".")

	upload, err = store.BeginUpload(protocol.FileUploadOpen{Path: "bad-digest", SHA256: strings.Repeat("00", 32), Existing: protocol.FileExistingFail})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := upload.Commit(); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("digest mismatch commit error = %v", err)
	}
	assertNoUploadStaging(t, rootDir, ".")
}

func TestFileTransferStoreRequiresExistingParentAndExplicitBounds(t *testing.T) {
	rootDir := t.TempDir()
	if _, err := OpenFileTransferStore("relative", 1024); err == nil {
		t.Fatal("accepted relative file transfer root")
	}
	if _, err := OpenFileTransferStore(rootDir, 0); err == nil {
		t.Fatal("accepted zero file transfer size limit")
	}
	if _, err := OpenFileTransferStore(rootDir, MaxFileTransferStoreBytes+1); err == nil {
		t.Fatal("accepted excessive file transfer size limit")
	}

	store, err := OpenFileTransferStore(rootDir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.BeginUpload(protocol.FileUploadOpen{Path: "missing/file", Existing: protocol.FileExistingFail}); err == nil {
		t.Fatal("upload created or accepted a missing parent directory")
	}
	expected := uint64(1025)
	if _, err := store.BeginUpload(protocol.FileUploadOpen{Path: "too-large", ExpectedSize: &expected, Existing: protocol.FileExistingFail}); err == nil {
		t.Fatal("accepted expected size above store limit")
	}
}

func assertNoUploadStaging(t *testing.T, rootDir, subdir string) {
	t.Helper()
	dir := rootDir
	if subdir != "." {
		dir = filepath.Join(rootDir, subdir)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".wedecent-upload-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("upload staging files remain: %#v", matches)
	}
}

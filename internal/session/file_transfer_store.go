package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"wedecent.com/wedecent/internal/protocol"
)

const MaxFileTransferStoreBytes uint64 = 1 << 40 // 1 TiB hard configuration ceiling.

// FileTransferStore confines future file-transfer operations beneath one
// operator-selected directory. It is a storage primitive, not authorization:
// callers must separately enforce the authenticated peer's file-operation
// policy before invoking it.
type FileTransferStore struct {
	root     *os.Root
	maxBytes uint64
}

func OpenFileTransferStore(rootPath string, maxBytes uint64) (*FileTransferStore, error) {
	rootPath = strings.TrimSpace(rootPath)
	if rootPath == "" || !filepath.IsAbs(rootPath) {
		return nil, errors.New("file transfer root must be an absolute path")
	}
	if maxBytes == 0 || maxBytes > MaxFileTransferStoreBytes {
		return nil, errors.New("file transfer size limit is out of range")
	}

	before, err := os.Lstat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("stat file transfer root: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("file transfer root must be an existing directory, not a symbolic link")
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open file transfer root: %w", err)
	}
	after, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("verify file transfer root: %w", err)
	}
	if !os.SameFile(before, after) {
		_ = root.Close()
		return nil, errors.New("file transfer root changed while it was being opened")
	}
	return &FileTransferStore{root: root, maxBytes: maxBytes}, nil
}

func (s *FileTransferStore) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
}

// OpenDownload opens one regular file after strict protocol validation. The
// final path component may not be a symlink. Intermediate symlinks are resolved
// only when os.Root can prove they remain beneath the configured root.
func (s *FileTransferStore) OpenDownload(open protocol.FileDownloadOpen) (*os.File, uint64, error) {
	if s == nil || s.root == nil {
		return nil, 0, errors.New("file transfer store is unavailable")
	}
	if err := protocol.ValidateFileDownloadOpen(open); err != nil {
		return nil, 0, err
	}

	observed, err := s.root.Lstat(open.Path)
	if err != nil {
		return nil, 0, fmt.Errorf("stat download: %w", err)
	}
	if observed.Mode()&os.ModeSymlink != 0 || !observed.Mode().IsRegular() {
		return nil, 0, errors.New("download target must be a regular file, not a symbolic link")
	}
	if observed.Size() < 0 || uint64(observed.Size()) > s.maxBytes {
		return nil, 0, errors.New("download exceeds the file transfer size limit")
	}

	file, err := s.root.Open(open.Path)
	if err != nil {
		return nil, 0, fmt.Errorf("open download: %w", err)
	}
	actual, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("verify download: %w", err)
	}
	if !actual.Mode().IsRegular() || !os.SameFile(observed, actual) {
		_ = file.Close()
		return nil, 0, errors.New("download target changed while it was being opened")
	}
	if actual.Size() < 0 || uint64(actual.Size()) > s.maxBytes {
		_ = file.Close()
		return nil, 0, errors.New("download exceeds the file transfer size limit")
	}
	return file, uint64(actual.Size()), nil
}

// BeginUpload creates a private staging file in the destination directory. This
// first runtime primitive deliberately supports only fail-if-exists publication;
// replace remains a reserved protocol policy until cross-platform replacement
// semantics are implemented and tested separately.
func (s *FileTransferStore) BeginUpload(open protocol.FileUploadOpen) (*FileUpload, error) {
	if s == nil || s.root == nil {
		return nil, errors.New("file transfer store is unavailable")
	}
	if err := protocol.ValidateFileUploadOpen(open); err != nil {
		return nil, err
	}
	if open.Existing != protocol.FileExistingFail {
		return nil, errors.New("file replacement is not supported")
	}
	if open.ExpectedSize != nil && *open.ExpectedSize > s.maxBytes {
		return nil, errors.New("expected upload size exceeds the file transfer size limit")
	}

	if _, err := s.root.Lstat(open.Path); err == nil {
		return nil, errors.New("upload destination already exists")
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat upload destination: %w", err)
	}

	parent := path.Dir(open.Path)
	if parent == "" {
		parent = "."
	}
	parentInfo, err := s.root.Stat(parent)
	if err != nil {
		return nil, fmt.Errorf("stat upload directory: %w", err)
	}
	if !parentInfo.IsDir() {
		return nil, errors.New("upload parent must be an existing directory")
	}

	for attempt := 0; attempt < 8; attempt++ {
		stageName, err := uploadStageName(parent)
		if err != nil {
			return nil, err
		}
		file, err := s.root.OpenFile(stageName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, fmt.Errorf("create upload staging file: %w", err)
		}
		return &FileUpload{
			root:       s.root,
			file:       file,
			stagePath:  stageName,
			destination: open.Path,
			expected:   open.ExpectedSize,
			expectedSHA: open.SHA256,
			maxBytes:   s.maxBytes,
			digest:     sha256.New(),
		}, nil
	}
	return nil, errors.New("could not allocate a private upload staging file")
}

func uploadStageName(parent string) (string, error) {
	var random [18]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", fmt.Errorf("generate upload staging name: %w", err)
	}
	name := ".wedecent-upload-" + hex.EncodeToString(random[:]) + ".tmp"
	if parent == "." {
		return name, nil
	}
	return parent + "/" + name, nil
}

type FileUpload struct {
	mu sync.Mutex

	root        *os.Root
	file        *os.File
	stagePath   string
	destination string
	expected    *uint64
	expectedSHA string
	maxBytes    uint64
	digest      hash.Hash
	written     uint64
	closed      bool
	committed   bool
}

func (u *FileUpload) Write(data []byte) (int, error) {
	if u == nil {
		return 0, errors.New("upload is unavailable")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, os.ErrClosed
	}
	if len(data) == 0 {
		return 0, nil
	}
	length := uint64(len(data))
	if length > u.maxBytes-u.written {
		return 0, u.failLocked(errors.New("upload exceeds the file transfer size limit"))
	}
	if u.expected != nil && length > *u.expected-u.written {
		return 0, u.failLocked(errors.New("upload exceeds the expected size"))
	}

	n, err := u.file.Write(data)
	if n > 0 {
		u.written += uint64(n)
		_, _ = u.digest.Write(data[:n])
	}
	if err != nil {
		return n, u.failLocked(fmt.Errorf("write upload staging file: %w", err))
	}
	if n != len(data) {
		return n, u.failLocked(io.ErrShortWrite)
	}
	return n, nil
}

func (u *FileUpload) Commit() error {
	if u == nil {
		return errors.New("upload is unavailable")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.committed {
		return nil
	}
	if u.closed {
		return os.ErrClosed
	}
	if u.expected != nil && u.written != *u.expected {
		return u.failLocked(errors.New("upload size does not match the expected size"))
	}
	if u.expectedSHA != "" && hex.EncodeToString(u.digest.Sum(nil)) != u.expectedSHA {
		return u.failLocked(errors.New("upload SHA-256 digest does not match"))
	}
	if err := u.file.Sync(); err != nil {
		return u.failLocked(fmt.Errorf("sync upload staging file: %w", err))
	}
	if err := u.file.Close(); err != nil {
		u.file = nil
		u.closed = true
		_ = u.root.Remove(u.stagePath)
		return fmt.Errorf("close upload staging file: %w", err)
	}
	u.file = nil

	// A hard-link publication is atomic and fails if destination already exists,
	// closing the race between the initial existence check and commit.
	if err := u.root.Link(u.stagePath, u.destination); err != nil {
		u.closed = true
		_ = u.root.Remove(u.stagePath)
		return fmt.Errorf("publish upload without overwrite: %w", err)
	}
	u.committed = true
	u.closed = true
	if err := u.root.Remove(u.stagePath); err != nil {
		return fmt.Errorf("upload committed but staging cleanup failed: %w", err)
	}
	return nil
}

func (u *FileUpload) Cancel() error {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.committed || u.closed {
		return nil
	}
	u.closed = true
	var closeErr error
	if u.file != nil {
		closeErr = u.file.Close()
		u.file = nil
	}
	removeErr := u.root.Remove(u.stagePath)
	if os.IsNotExist(removeErr) {
		removeErr = nil
	}
	return errors.Join(closeErr, removeErr)
}

func (u *FileUpload) Close() error { return u.Cancel() }

func (u *FileUpload) failLocked(cause error) error {
	u.closed = true
	if u.file != nil {
		_ = u.file.Close()
		u.file = nil
	}
	_ = u.root.Remove(u.stagePath)
	return cause
}

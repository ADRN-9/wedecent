package updateinfo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultInstallerFetchTimeout = 2 * time.Minute
	MaxInstallerArchiveBytes     = int64(512 << 20)
)

var ErrInstallerStage = errors.New("updateinfo: installer staging failed")

// StagedInstaller describes a verified installer archive downloaded from the
// exact immutable URL authenticated by a signed update manifest. Path points to
// a private temporary file owned by the caller; callers must remove it when no
// longer needed.
type StagedInstaller struct {
	Path   string
	Size   int64
	SHA256 string
}

// InstallerClient downloads the immutable installer archive named by an
// already-authenticated Manifest. Transport is injectable for tests; production
// callers should normally leave it nil so the default HTTPS transport is used.
type InstallerClient struct {
	Transport http.RoundTripper
	Timeout   time.Duration
	MaxBytes  int64
}

// Stage downloads and verifies the installer archive into stagingDir. It never
// follows redirects, never overwrites an existing path, and removes partial or
// hash-mismatched files before returning an error.
//
// A successful return proves the bytes matched manifest.InstallerSHA256 at the
// end of this call. A later installer-execution boundary must call
// VerifyStagedInstaller immediately before consuming the file so a mutable
// local path is never treated as permanently trusted.
func (c InstallerClient) Stage(ctx context.Context, manifest Manifest, stagingDir string) (StagedInstaller, error) {
	var zero StagedInstaller
	if err := manifest.Validate(); err != nil {
		return zero, err
	}
	if stagingDir == "" {
		return zero, fmt.Errorf("%w: staging directory is required", ErrInstallerStage)
	}
	if c.Timeout < 0 {
		return zero, fmt.Errorf("%w: timeout must not be negative", ErrInstallerStage)
	}
	limit, err := c.maxBytes()
	if err != nil {
		return zero, err
	}
	stagingDir, err = filepath.Abs(stagingDir)
	if err != nil {
		return zero, fmt.Errorf("%w: resolve staging directory: %v", ErrInstallerStage, err)
	}
	if err := ensurePrivateStateDir(stagingDir); err != nil {
		return zero, fmt.Errorf("%w: prepare staging directory: %v", ErrInstallerStage, err)
	}

	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultInstallerFetchTimeout
	}
	client := &http.Client{
		Transport: c.Transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("%w: redirects are not permitted", ErrInstallerStage)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.InstallerURL, nil)
	if err != nil {
		return zero, fmt.Errorf("%w: build installer request", ErrInstallerStage)
	}
	req.Header.Set("Accept", "application/zip, application/octet-stream;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return zero, fmt.Errorf("%w: fetch installer: %w", ErrInstallerStage, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("%w: installer fetch returned HTTP %d", ErrInstallerStage, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return zero, fmt.Errorf("%w: installer exceeds %d bytes", ErrInstallerStage, limit)
	}

	pattern := fmt.Sprintf(".wedecent-%s-installer-*.zip", manifest.Version)
	file, err := os.CreateTemp(stagingDir, pattern)
	if err != nil {
		return zero, fmt.Errorf("%w: create installer staging file: %v", ErrInstallerStage, err)
	}
	path := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return zero, fmt.Errorf("%w: protect installer staging file: %v", ErrInstallerStage, err)
	}

	digest := sha256.New()
	size, err := copyInstaller(file, digest, resp.Body, limit)
	if err != nil {
		return zero, err
	}
	if resp.ContentLength >= 0 && size != resp.ContentLength {
		return zero, fmt.Errorf("%w: installer response length mismatch", ErrInstallerStage)
	}
	if size == 0 {
		return zero, fmt.Errorf("%w: installer response is empty", ErrInstallerStage)
	}
	actualHash := hex.EncodeToString(digest.Sum(nil))
	if actualHash != manifest.InstallerSHA256 {
		return zero, fmt.Errorf("%w: installer SHA-256 mismatch", ErrInstallerStage)
	}
	if err := file.Sync(); err != nil {
		return zero, fmt.Errorf("%w: sync installer staging file: %v", ErrInstallerStage, err)
	}
	if err := file.Close(); err != nil {
		return zero, fmt.Errorf("%w: close installer staging file: %v", ErrInstallerStage, err)
	}
	keep = true
	return StagedInstaller{Path: filepath.Clean(path), Size: size, SHA256: actualHash}, nil
}

// VerifyStagedInstaller revalidates a staged archive immediately before a later
// trusted boundary consumes it. It rejects symlinks, non-regular files, empty
// or oversized files, path replacement between inspection and open, and any
// byte change relative to the signed manifest.
func VerifyStagedInstaller(manifest Manifest, path string, maxBytes int64) (StagedInstaller, error) {
	var zero StagedInstaller
	if err := manifest.Validate(); err != nil {
		return zero, err
	}
	if path == "" {
		return zero, fmt.Errorf("%w: staged installer path is required", ErrInstallerStage)
	}
	limit, err := installerSizeLimit(maxBytes)
	if err != nil {
		return zero, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return zero, fmt.Errorf("%w: resolve staged installer path: %v", ErrInstallerStage, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return zero, fmt.Errorf("%w: stat staged installer: %v", ErrInstallerStage, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return zero, fmt.Errorf("%w: staged installer must be a regular non-symlink file", ErrInstallerStage)
	}
	if info.Size() <= 0 || info.Size() > limit {
		return zero, fmt.Errorf("%w: staged installer size is invalid", ErrInstallerStage)
	}
	file, err := os.Open(path)
	if err != nil {
		return zero, fmt.Errorf("%w: open staged installer: %v", ErrInstallerStage, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return zero, fmt.Errorf("%w: stat opened staged installer: %v", ErrInstallerStage, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return zero, fmt.Errorf("%w: staged installer path changed before open", ErrInstallerStage)
	}

	digest := sha256.New()
	size, err := copyInstaller(io.Discard, digest, file, limit)
	if err != nil {
		return zero, err
	}
	if size != info.Size() {
		return zero, fmt.Errorf("%w: staged installer changed while reading", ErrInstallerStage)
	}
	actualHash := hex.EncodeToString(digest.Sum(nil))
	if actualHash != manifest.InstallerSHA256 {
		return zero, fmt.Errorf("%w: installer SHA-256 mismatch", ErrInstallerStage)
	}
	return StagedInstaller{Path: filepath.Clean(path), Size: size, SHA256: actualHash}, nil
}

func (c InstallerClient) maxBytes() (int64, error) {
	return installerSizeLimit(c.MaxBytes)
}

func installerSizeLimit(limit int64) (int64, error) {
	if limit < 0 {
		return 0, fmt.Errorf("%w: maximum installer size must not be negative", ErrInstallerStage)
	}
	if limit == 0 {
		return MaxInstallerArchiveBytes, nil
	}
	if limit > MaxInstallerArchiveBytes {
		return 0, fmt.Errorf("%w: maximum installer size exceeds hard limit", ErrInstallerStage)
	}
	return limit, nil
}

func copyInstaller(dst io.Writer, digest hash.Hash, src io.Reader, limit int64) (int64, error) {
	written, err := io.Copy(io.MultiWriter(dst, digest), io.LimitReader(src, limit+1))
	if err != nil {
		return 0, fmt.Errorf("%w: read installer response: %w", ErrInstallerStage, err)
	}
	if written > limit {
		return 0, fmt.Errorf("%w: installer exceeds %d bytes", ErrInstallerStage, limit)
	}
	return written, nil
}

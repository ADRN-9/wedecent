package updateinfo

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const MaxInstallerExpandedBytes = int64(1 << 30)

var ErrInstallerPackage = errors.New("updateinfo: installer package verification failed")

var (
	installerBinaries = []string{"wd.exe", "wd-agent.exe", "wd-routerctl.exe", "wd-core.exe", "wd-ui.exe"}
	installerScripts  = []string{"Install-WeDecent.ps1", "Uninstall-WeDecent.ps1", "Test-WeDecentInstall.ps1"}
	installerFiles    = []string{
		"wd.exe", "wd-agent.exe", "wd-routerctl.exe", "wd-core.exe", "wd-ui.exe",
		"VERSION.txt", "SHA256SUMS.txt",
		"Install-WeDecent.ps1", "Uninstall-WeDecent.ps1", "Test-WeDecentInstall.ps1",
		"README.md", "PACKAGE_SHA256SUMS.txt",
	}
	installerPayloadFiles = []string{
		"wd.exe", "wd-agent.exe", "wd-routerctl.exe", "wd-core.exe", "wd-ui.exe",
		"VERSION.txt", "SHA256SUMS.txt",
		"Install-WeDecent.ps1", "Uninstall-WeDecent.ps1", "Test-WeDecentInstall.ps1",
		"README.md",
	}
)

// AuthenticodeVerifier is the policy boundary for Windows signature trust. A
// production implementation must reject any file that does not satisfy the
// approved publisher, certificate-chain, signature-validity, and timestamp
// policy. Verification errors must not expose certificate or file contents.
type AuthenticodeVerifier func(context.Context, string) error

// VerifiedInstallerPackage is valid only for the duration of the consumer
// callback passed to WithVerifiedInstallerPackage. Dir is removed immediately
// after the callback returns.
type VerifiedInstallerPackage struct {
	Dir     string
	Version string
}

// WithVerifiedInstallerPackage revalidates the staged archive and opens the
// package trust boundary immediately around a caller-provided consumer. It
// verifies the exact archive shape, bounded expansion, version metadata, both
// checksum manifests, and Authenticode policy for all five binaries and three
// installer scripts before consumer is called.
//
// The extracted directory is private temporary state and is removed after the
// callback. The consumer must not retain paths from pkg after returning.
func WithVerifiedInstallerPackage(
	ctx context.Context,
	manifest Manifest,
	stagedPath string,
	maxArchiveBytes int64,
	verifyAuthenticode AuthenticodeVerifier,
	consumer func(context.Context, VerifiedInstallerPackage) error,
) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if verifyAuthenticode == nil {
		return fmt.Errorf("%w: Authenticode verifier is required", ErrInstallerPackage)
	}
	if consumer == nil {
		return fmt.Errorf("%w: package consumer is required", ErrInstallerPackage)
	}
	if _, err := VerifyStagedInstaller(manifest, stagedPath, maxArchiveBytes); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	archivePath, err := filepath.Abs(stagedPath)
	if err != nil {
		return fmt.Errorf("%w: resolve archive path: %v", ErrInstallerPackage, err)
	}
	root := filepath.Dir(archivePath)
	if err := ensurePrivateStateDir(root); err != nil {
		return fmt.Errorf("%w: protect package staging directory: %v", ErrInstallerPackage, err)
	}
	tmpDir, err := os.MkdirTemp(root, ".wedecent-verified-package-*")
	if err != nil {
		return fmt.Errorf("%w: create verification directory: %v", ErrInstallerPackage, err)
	}
	defer os.RemoveAll(tmpDir)
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return fmt.Errorf("%w: protect verification directory: %v", ErrInstallerPackage, err)
	}

	if err := extractInstallerPackage(ctx, archivePath, tmpDir); err != nil {
		return err
	}
	if err := verifyInstallerVersion(tmpDir, manifest.Version); err != nil {
		return err
	}
	if err := verifyChecksumManifest(filepath.Join(tmpDir, "SHA256SUMS.txt"), tmpDir, installerBinaries); err != nil {
		return err
	}
	if err := verifyChecksumManifest(filepath.Join(tmpDir, "PACKAGE_SHA256SUMS.txt"), tmpDir, installerPayloadFiles); err != nil {
		return err
	}
	for _, name := range append(append([]string{}, installerBinaries...), installerScripts...) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyAuthenticode(ctx, filepath.Join(tmpDir, name)); err != nil {
			return fmt.Errorf("%w: Authenticode policy rejected %s", ErrInstallerPackage, name)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := consumer(ctx, VerifiedInstallerPackage{Dir: tmpDir, Version: manifest.Version}); err != nil {
		return err
	}
	return nil
}

func extractInstallerPackage(ctx context.Context, archivePath, dst string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("%w: open ZIP: %v", ErrInstallerPackage, err)
	}
	defer reader.Close()

	if len(reader.File) != len(installerFiles) {
		return fmt.Errorf("%w: archive must contain exactly %d files", ErrInstallerPackage, len(installerFiles))
	}
	expected := make(map[string]struct{}, len(installerFiles))
	for _, name := range installerFiles {
		expected[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(installerFiles))
	var expanded int64
	for _, member := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := member.Name
		if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) || member.FileInfo().IsDir() {
			return fmt.Errorf("%w: invalid archive member path", ErrInstallerPackage)
		}
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("%w: unexpected archive member", ErrInstallerPackage)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("%w: duplicate archive member", ErrInstallerPackage)
		}
		seen[name] = struct{}{}
		if member.UncompressedSize64 == 0 || member.UncompressedSize64 > uint64(MaxInstallerExpandedBytes) {
			return fmt.Errorf("%w: invalid archive member size", ErrInstallerPackage)
		}
		if member.UncompressedSize64 > uint64(MaxInstallerExpandedBytes-int64(expanded)) {
			return fmt.Errorf("%w: expanded package exceeds %d bytes", ErrInstallerPackage, MaxInstallerExpandedBytes)
		}
		expanded += int64(member.UncompressedSize64)
		if err := extractInstallerMember(member, filepath.Join(dst, name)); err != nil {
			return err
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: archive is missing required files", ErrInstallerPackage)
	}
	return nil
}

func extractInstallerMember(member *zip.File, dst string) error {
	src, err := member.Open()
	if err != nil {
		return fmt.Errorf("%w: open archive member", ErrInstallerPackage)
	}
	defer src.Close()
	file, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create extracted member", ErrInstallerPackage)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()
	written, err := io.Copy(file, io.LimitReader(src, int64(member.UncompressedSize64)+1))
	if err != nil {
		return fmt.Errorf("%w: extract archive member", ErrInstallerPackage)
	}
	if written != int64(member.UncompressedSize64) {
		return fmt.Errorf("%w: archive member length mismatch", ErrInstallerPackage)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("%w: sync extracted member", ErrInstallerPackage)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("%w: close extracted member", ErrInstallerPackage)
	}
	ok = true
	return nil
}

func verifyInstallerVersion(dir, version string) error {
	data, err := os.ReadFile(filepath.Join(dir, "VERSION.txt"))
	if err != nil {
		return fmt.Errorf("%w: read VERSION.txt", ErrInstallerPackage)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	count := 0
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "version=") {
			count++
			if scanner.Text() != "version="+strings.TrimPrefix(version, "v") {
				return fmt.Errorf("%w: VERSION.txt does not match manifest", ErrInstallerPackage)
			}
		}
	}
	if err := scanner.Err(); err != nil || count != 1 {
		return fmt.Errorf("%w: VERSION.txt version entry is invalid", ErrInstallerPackage)
	}
	return nil
}

func verifyChecksumManifest(path, dir string, expectedNames []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: read checksum manifest", ErrInstallerPackage)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != len(expectedNames) {
		return fmt.Errorf("%w: checksum manifest entry count is invalid", ErrInstallerPackage)
	}
	expected := make(map[string]struct{}, len(expectedNames))
	for _, name := range expectedNames {
		expected[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(expectedNames))
	for _, line := range lines {
		if len(line) < 67 || line[64:66] != "  " {
			return fmt.Errorf("%w: malformed checksum manifest", ErrInstallerPackage)
		}
		digestText, name := line[:64], line[66:]
		if strings.ToLower(digestText) != digestText || len(name) == 0 || filepath.Base(name) != name {
			return fmt.Errorf("%w: malformed checksum manifest", ErrInstallerPackage)
		}
		decoded, err := hex.DecodeString(digestText)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("%w: malformed checksum manifest", ErrInstallerPackage)
		}
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("%w: checksum manifest contains unexpected file", ErrInstallerPackage)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("%w: checksum manifest contains duplicate file", ErrInstallerPackage)
		}
		seen[name] = struct{}{}
		actual, err := hashRegularFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if actual != digestText {
			return fmt.Errorf("%w: checksum mismatch for %s", ErrInstallerPackage, name)
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: checksum manifest does not cover expected files", ErrInstallerPackage)
	}
	return nil
}

func hashRegularFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: package member is not a regular file", ErrInstallerPackage)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%w: open package member", ErrInstallerPackage)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("%w: hash package member", ErrInstallerPackage)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

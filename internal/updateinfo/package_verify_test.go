package updateinfo

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestWithVerifiedInstallerPackageAcceptsExactPackage(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	path := writeStagedArchive(t, archive)
	manifest.InstallerSHA256 = sha256Hex(archive)

	var verified []string
	var callbackDir string
	err := WithVerifiedInstallerPackage(
		context.Background(),
		manifest,
		path,
		0,
		func(_ context.Context, path string) error {
			verified = append(verified, filepath.Base(path))
			return nil
		},
		func(_ context.Context, pkg VerifiedInstallerPackage) error {
			callbackDir = pkg.Dir
			if pkg.Version != manifest.Version {
				t.Fatalf("consumer version = %q, want %q", pkg.Version, manifest.Version)
			}
			for _, name := range installerFiles {
				if _, err := os.Stat(filepath.Join(pkg.Dir, name)); err != nil {
					t.Fatalf("consumer missing %s: %v", name, err)
				}
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("WithVerifiedInstallerPackage() error = %v", err)
	}
	sort.Strings(verified)
	wantSigned := append(append([]string{}, installerBinaries...), installerScripts...)
	sort.Strings(wantSigned)
	if strings.Join(verified, ",") != strings.Join(wantSigned, ",") {
		t.Fatalf("verified files = %v, want %v", verified, wantSigned)
	}
	if callbackDir == "" {
		t.Fatal("consumer was not called")
	}
	if _, err := os.Stat(callbackDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verified package directory still exists after callback: %v", err)
	}
}

func TestWithVerifiedInstallerPackageRequiresVerifierAndConsumer(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	path := writeStagedArchive(t, archive)
	manifest.InstallerSHA256 = sha256Hex(archive)

	if err := WithVerifiedInstallerPackage(context.Background(), manifest, path, 0, nil, func(context.Context, VerifiedInstallerPackage) error { return nil }); !errors.Is(err, ErrInstallerPackage) {
		t.Fatalf("nil verifier error = %v", err)
	}
	if err := WithVerifiedInstallerPackage(context.Background(), manifest, path, 0, func(context.Context, string) error { return nil }, nil); !errors.Is(err, ErrInstallerPackage) {
		t.Fatalf("nil consumer error = %v", err)
	}
}

func TestWithVerifiedInstallerPackageRejectsShapeAndMetadataDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string][]byte)
	}{
		{
			name: "unexpected file",
			mutate: func(files map[string][]byte) {
				files["extra.txt"] = []byte("extra")
			},
		},
		{
			name: "wrong version",
			mutate: func(files map[string][]byte) {
				files["VERSION.txt"] = []byte("version=9.9.9\ncommit=test\nbuilt_at=2026-01-01T00:00:00Z\ngo=go1.27.0\nplatform=windows/amd64\n")
				rebuildPackageManifest(files)
			},
		},
		{
			name: "binary checksum mismatch",
			mutate: func(files map[string][]byte) {
				files["wd.exe"] = []byte("tampered")
				rebuildPackageManifest(files)
			},
		},
		{
			name: "package checksum mismatch",
			mutate: func(files map[string][]byte) {
				files["README.md"] = []byte("tampered readme")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, archive := buildInstallerPackageFixture(t, test.mutate)
			path := writeStagedArchive(t, archive)
			manifest.InstallerSHA256 = sha256Hex(archive)
			called := false
			err := WithVerifiedInstallerPackage(
				context.Background(), manifest, path, 0,
				func(context.Context, string) error { return nil },
				func(context.Context, VerifiedInstallerPackage) error { called = true; return nil },
			)
			if !errors.Is(err, ErrInstallerPackage) {
				t.Fatalf("error = %v, want ErrInstallerPackage", err)
			}
			if called {
				t.Fatal("consumer was called for invalid package")
			}
		})
	}
}

func TestWithVerifiedInstallerPackageRejectsAuthenticodeFailure(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	path := writeStagedArchive(t, archive)
	manifest.InstallerSHA256 = sha256Hex(archive)
	called := false
	err := WithVerifiedInstallerPackage(
		context.Background(), manifest, path, 0,
		func(_ context.Context, path string) error {
			if filepath.Base(path) == "wd-core.exe" {
				return errors.New("untrusted signer")
			}
			return nil
		},
		func(context.Context, VerifiedInstallerPackage) error { called = true; return nil },
	)
	if !errors.Is(err, ErrInstallerPackage) {
		t.Fatalf("error = %v, want ErrInstallerPackage", err)
	}
	if called {
		t.Fatal("consumer was called after Authenticode failure")
	}
	if strings.Contains(err.Error(), "untrusted signer") {
		t.Fatalf("raw verifier error leaked: %v", err)
	}
}

func TestWithVerifiedInstallerPackageRechecksStagedArchive(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	path := writeStagedArchive(t, archive)
	manifest.InstallerSHA256 = sha256Hex(archive)
	if err := os.WriteFile(path, append(archive, 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WithVerifiedInstallerPackage(
		context.Background(), manifest, path, 0,
		func(context.Context, string) error { return nil },
		func(context.Context, VerifiedInstallerPackage) error { return nil },
	)
	if !errors.Is(err, ErrInstallerStage) {
		t.Fatalf("error = %v, want ErrInstallerStage", err)
	}
}

func TestWithVerifiedInstallerPackagePropagatesCancellation(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	path := writeStagedArchive(t, archive)
	manifest.InstallerSHA256 = sha256Hex(archive)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := WithVerifiedInstallerPackage(
		ctx, manifest, path, 0,
		func(context.Context, string) error { called = true; return nil },
		func(context.Context, VerifiedInstallerPackage) error { called = true; return nil },
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if called {
		t.Fatal("verification or consumer called after cancellation")
	}
}

func buildInstallerPackageFixture(t *testing.T, mutate func(map[string][]byte)) (Manifest, []byte) {
	t.Helper()
	files := map[string][]byte{
		"wd.exe":                   []byte("wd binary"),
		"wd-agent.exe":             []byte("agent binary"),
		"wd-routerctl.exe":         []byte("routerctl binary"),
		"wd-core.exe":              []byte("core binary"),
		"wd-ui.exe":                []byte("ui binary"),
		"VERSION.txt":              []byte("version=0.4.0\ncommit=test\nbuilt_at=2026-01-01T00:00:00Z\ngo=go1.27.0\nplatform=windows/amd64\n"),
		"Install-WeDecent.ps1":     []byte("Write-Output install\n"),
		"Uninstall-WeDecent.ps1":   []byte("Write-Output uninstall\n"),
		"Test-WeDecentInstall.ps1": []byte("Write-Output test\n"),
		"README.md":                []byte("installer readme\n"),
	}
	files["SHA256SUMS.txt"] = checksumManifest(files, installerBinaries)
	files["PACKAGE_SHA256SUMS.txt"] = checksumManifest(files, installerPayloadFiles)
	if mutate != nil {
		mutate(files)
	}

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Store}
		header.SetMode(0o600)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	manifest := Manifest{
		Schema:          ManifestSchemaV1,
		Channel:         StableChannel,
		Sequence:        1,
		Version:         "v0.4.0",
		PublishedAt:     "2026-01-01T00:00:00Z",
		ReleaseURL:      "https://downloads.wedecent.com/windows/v0.4.0/wedecent-v0.4.0-windows-amd64.zip",
		ReleaseSHA256:   strings.Repeat("0", 64),
		InstallerURL:    "https://downloads.wedecent.com/windows/v0.4.0/wedecent-v0.4.0-windows-installer.zip",
		InstallerSHA256: strings.Repeat("0", 64),
	}
	return manifest, buffer.Bytes()
}

func checksumManifest(files map[string][]byte, names []string) []byte {
	sorted := append([]string{}, names...)
	sort.Strings(sorted)
	var builder strings.Builder
	for _, name := range sorted {
		fmt.Fprintf(&builder, "%s  %s\n", sha256Hex(files[name]), name)
	}
	return []byte(builder.String())
}

func rebuildPackageManifest(files map[string][]byte) {
	files["PACKAGE_SHA256SUMS.txt"] = checksumManifest(files, installerPayloadFiles)
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func writeStagedArchive(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "installer.zip")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

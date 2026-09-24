package updateinfo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type installerRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f installerRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestInstallerClientStageAndReverify(t *testing.T) {
	payload := []byte("verified installer zip bytes")
	manifest := installerTestManifest(payload)
	var requestedURL string
	client := InstallerClient{
		Transport: installerRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			requestedURL = req.URL.String()
			return &http.Response{
				StatusCode:    http.StatusOK,
				Body:          io.NopCloser(bytes.NewReader(payload)),
				ContentLength: int64(len(payload)),
				Header:        make(http.Header),
				Request:       req,
			}, nil
		}),
	}
	stagingDir := filepath.Join(t.TempDir(), "updates")
	staged, err := client.Stage(context.Background(), manifest, stagingDir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(staged.Path)
	if requestedURL != manifest.InstallerURL {
		t.Fatalf("requested %q, want %q", requestedURL, manifest.InstallerURL)
	}
	if staged.Size != int64(len(payload)) || staged.SHA256 != manifest.InstallerSHA256 {
		t.Fatalf("unexpected staged metadata: %+v", staged)
	}
	if filepath.Dir(staged.Path) != stagingDir {
		t.Fatalf("staged path escaped directory: %q", staged.Path)
	}
	contents, err := os.ReadFile(staged.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, payload) {
		t.Fatal("staged bytes changed")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(staged.Path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("staged mode = %o, want 600", got)
		}
	}
	verified, err := VerifyStagedInstaller(manifest, staged.Path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if verified != staged {
		t.Fatalf("reverified metadata = %+v, want %+v", verified, staged)
	}
}

func TestInstallerClientHashMismatchRemovesPartialFile(t *testing.T) {
	payload := []byte("wrong bytes")
	manifest := installerTestManifest([]byte("expected bytes"))
	client := InstallerClient{
		Transport: staticInstallerResponse(http.StatusOK, payload, int64(len(payload))),
	}
	stagingDir := filepath.Join(t.TempDir(), "updates")
	_, err := client.Stage(context.Background(), manifest, stagingDir)
	if !errors.Is(err, ErrInstallerStage) || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("Stage error = %v", err)
	}
	assertDirectoryEmpty(t, stagingDir)
}

func TestInstallerClientRejectsStreamedOversizeAndCleansUp(t *testing.T) {
	payload := []byte("12345")
	manifest := installerTestManifest(payload)
	client := InstallerClient{
		Transport: staticInstallerResponse(http.StatusOK, payload, -1),
		MaxBytes:  4,
	}
	stagingDir := filepath.Join(t.TempDir(), "updates")
	_, err := client.Stage(context.Background(), manifest, stagingDir)
	if !errors.Is(err, ErrInstallerStage) || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("Stage error = %v", err)
	}
	assertDirectoryEmpty(t, stagingDir)
}

func TestInstallerClientRejectsKnownOversizeBeforeCreatingFile(t *testing.T) {
	payload := []byte("12345")
	manifest := installerTestManifest(payload)
	client := InstallerClient{
		Transport: staticInstallerResponse(http.StatusOK, payload, int64(len(payload))),
		MaxBytes:  4,
	}
	stagingDir := filepath.Join(t.TempDir(), "updates")
	_, err := client.Stage(context.Background(), manifest, stagingDir)
	if !errors.Is(err, ErrInstallerStage) || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("Stage error = %v", err)
	}
	assertDirectoryEmpty(t, stagingDir)
}

func TestInstallerClientRejectsRedirect(t *testing.T) {
	payload := []byte("unused")
	manifest := installerTestManifest(payload)
	calls := 0
	client := InstallerClient{
		Transport: installerRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Header: http.Header{
					"Location": []string{"https://example.com/other.zip"},
				},
				Request: req,
			}, nil
		}),
	}
	_, err := client.Stage(context.Background(), manifest, filepath.Join(t.TempDir(), "updates"))
	if !errors.Is(err, ErrInstallerStage) || !strings.Contains(err.Error(), "redirects are not permitted") {
		t.Fatalf("Stage error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want 1", calls)
	}
}

func TestInstallerClientPreservesCancellation(t *testing.T) {
	payload := []byte("unused")
	manifest := installerTestManifest(payload)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := InstallerClient{
		Transport: installerRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}),
	}
	_, err := client.Stage(ctx, manifest, filepath.Join(t.TempDir(), "updates"))
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrInstallerStage) {
		t.Fatalf("Stage error = %v", err)
	}
}

func TestInstallerClientRejectsInvalidConfiguration(t *testing.T) {
	manifest := installerTestManifest([]byte("payload"))
	for name, client := range map[string]InstallerClient{
		"negative timeout": {Timeout: -1},
		"negative limit":   {MaxBytes: -1},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := client.Stage(context.Background(), manifest, filepath.Join(t.TempDir(), "updates"))
			if !errors.Is(err, ErrInstallerStage) {
				t.Fatalf("Stage error = %v", err)
			}
		})
	}
}

func TestVerifyStagedInstallerRejectsMutationAndSymlink(t *testing.T) {
	payload := []byte("expected installer")
	manifest := installerTestManifest(payload)
	path := filepath.Join(t.TempDir(), "installer.zip")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStagedInstaller(manifest, path, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed installer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStagedInstaller(manifest, path, 0); !errors.Is(err, ErrInstallerStage) {
		t.Fatalf("mutated verify error = %v", err)
	}

	target := filepath.Join(t.TempDir(), "target.zip")
	if err := os.WriteFile(target, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	link := target + ".link"
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := VerifyStagedInstaller(manifest, link, 0); !errors.Is(err, ErrInstallerStage) {
		t.Fatalf("symlink verify error = %v", err)
	}
}

func TestVerifyStagedInstallerRejectsInvalidSizeLimit(t *testing.T) {
	manifest := installerTestManifest([]byte("payload"))
	path := filepath.Join(t.TempDir(), "installer.zip")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStagedInstaller(manifest, path, -1); !errors.Is(err, ErrInstallerStage) {
		t.Fatalf("VerifyStagedInstaller error = %v", err)
	}
}

func staticInstallerResponse(status int, body []byte, contentLength int64) http.RoundTripper {
	return installerRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    status,
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: contentLength,
			Header:        make(http.Header),
			Request:       req,
		}, nil
	})
}

func installerTestManifest(installer []byte) Manifest {
	digest := sha256.Sum256(installer)
	return Manifest{
		Schema:          ManifestSchemaV1,
		Channel:         StableChannel,
		Sequence:        42,
		Version:         "v1.2.3",
		PublishedAt:     "2026-09-23T20:00:00Z",
		ReleaseURL:      "https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-amd64.zip",
		ReleaseSHA256:   strings.Repeat("a", 64),
		InstallerURL:    "https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-installer.zip",
		InstallerSHA256: hex.EncodeToString(digest[:]),
	}
}

func assertDirectoryEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory contains %d entries after failed staging", len(entries))
	}
}

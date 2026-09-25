package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestEnsureRejectsSymlinkedCertificateWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	if _, err := Ensure(dir, "test-device"); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "identity.crt")
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}

	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "target")
	want := []byte("do-not-touch")
	if err := os.WriteFile(target, want, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, certPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := Ensure(dir, "test-device"); err == nil {
		t.Fatal("Ensure accepted symlinked identity certificate")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("symlink target content changed: %q", got)
	}
	if runtime.GOOS != "windows" && after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("symlink target mode changed from %o to %o", before.Mode().Perm(), after.Mode().Perm())
	}
}

func TestLoadCertificateRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.crt")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxIdentityCertificateFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := loadCertificate(path)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("loadCertificate() error = %v, want oversized-file error", err)
	}
}

func TestEnsureRepairsInvalidRegularCertificate(t *testing.T) {
	dir := t.TempDir()
	first, err := Ensure(dir, "test-device")
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "identity.crt")
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	repaired, err := Ensure(dir, "test-device")
	if err != nil {
		t.Fatal(err)
	}
	if repaired.ID != first.ID {
		t.Fatalf("identity changed during certificate repair: got %q want %q", repaired.ID, first.ID)
	}
	if _, err := loadCertificate(certPath); err != nil {
		t.Fatalf("load repaired certificate: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(certPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("certificate mode = %o, want 644", info.Mode().Perm())
		}
	}
}

func TestEnsureConcurrentCertificateCreationConverges(t *testing.T) {
	dir := t.TempDir()
	first, err := Ensure(dir, "test-device")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "identity.crt")); err != nil {
		t.Fatal(err)
	}

	const callers = 32
	start := make(chan struct{})
	ids := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			<-start
			id, err := Ensure(dir, "test-device")
			if err != nil {
				errs <- err
				return
			}
			ids <- id.ID
		}()
	}
	close(start)
	wg.Wait()
	close(ids)
	close(errs)

	for err := range errs {
		t.Fatalf("Ensure() error = %v", err)
	}
	count := 0
	for id := range ids {
		count++
		if id != first.ID {
			t.Fatalf("concurrent Ensure() returned identity %q, want %q", id, first.ID)
		}
	}
	if count != callers {
		t.Fatalf("successful callers = %d, want %d", count, callers)
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("Load() after concurrent certificate creation: %v", err)
	}
}

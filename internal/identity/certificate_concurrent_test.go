package identity

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConcurrentlyCreatedCertificateWaitsForCompleteFile(t *testing.T) {
	sourceDir := t.TempDir()
	if _, err := Ensure(sourceDir, "concurrent-source"); err != nil {
		t.Fatal(err)
	}
	complete, err := os.ReadFile(filepath.Join(sourceDir, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "identity.crt")
	partialLen := len(complete) / 2
	if partialLen == 0 {
		t.Fatal("certificate fixture is empty")
	}
	if err := os.WriteFile(target, complete[:partialLen], 0o644); err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		writeDone <- os.WriteFile(target, complete, 0o644)
	}()

	cert, err := loadConcurrentlyCreatedCertificate(target)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Fatal("concurrent certificate load returned nil certificate")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

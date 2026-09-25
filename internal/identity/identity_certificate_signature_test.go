package identity

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityCertificateTamperedSignatureFailsClosedAndEnsureRepairs(t *testing.T) {
	dir := t.TempDir()
	first, err := Ensure(dir, "test-device")
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(dir, "identity.crt")
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("identity certificate is not a single certificate PEM block")
	}
	if len(block.Bytes) == 0 {
		t.Fatal("identity certificate DER is empty")
	}

	// For an Ed25519 X.509 certificate, the signature BIT STRING is the final
	// field. Altering its last byte keeps the DER and public key parseable while
	// making the self-signature invalid.
	tamperedDER := append([]byte(nil), block.Bytes...)
	tamperedDER[len(tamperedDER)-1] ^= 0x01
	tamperedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tamperedDER,
	})
	if err := os.WriteFile(certPath, tamperedPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadCertificate(certPath); err == nil ||
		!strings.Contains(err.Error(), "self-signature") {
		t.Fatalf(
			"loadCertificate() error = %v, want self-signature rejection",
			err,
		)
	}
	if _, err := Load(dir); err == nil ||
		!strings.Contains(err.Error(), "self-signature") {
		t.Fatalf("Load() error = %v, want self-signature rejection", err)
	}

	repaired, err := Ensure(dir, "test-device")
	if err != nil {
		t.Fatal(err)
	}
	if repaired.ID != first.ID {
		t.Fatalf(
			"identity changed during certificate signature repair: got %q want %q",
			repaired.ID,
			first.ID,
		)
	}
	if _, err := loadCertificate(certPath); err != nil {
		t.Fatalf("load repaired certificate: %v", err)
	}
}

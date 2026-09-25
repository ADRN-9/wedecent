package identity

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type opaqueIdentitySigner struct {
	crypto.Signer
}

func TestIssueCertificateAcceptsOpaqueEd25519Signer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &opaqueIdentitySigner{Signer: priv}
	path := filepath.Join(t.TempDir(), "identity.crt")

	leaf, err := issueCertificate(
		path,
		"opaque-signer",
		DeviceID(pub),
		pub,
		signer,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignature(
		leaf.SignatureAlgorithm,
		leaf.RawTBSCertificate,
		leaf.Signature,
	); err != nil {
		t.Fatalf("certificate self-signature: %v", err)
	}

	cert := tlsCertificateFor(leaf, signer)
	if cert.PrivateKey != signer {
		t.Fatal("TLS certificate did not retain opaque signer")
	}
	if cert.Leaf != leaf {
		t.Fatal("TLS certificate leaf changed")
	}
}

func TestIssueCertificateRejectsSignerPublicKeyMismatch(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.crt")

	_, err = issueCertificate(
		path,
		"mismatched-signer",
		DeviceID(pub),
		pub,
		&opaqueIdentitySigner{Signer: otherPriv},
		false,
	)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("issueCertificate() error = %v, want signer mismatch", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("mismatched signer created certificate file: stat error = %v", statErr)
	}
}

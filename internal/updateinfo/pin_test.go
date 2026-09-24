package updateinfo

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestProvisionedPublicKey(t *testing.T) {
	original := provisionedPublicKeyText
	t.Cleanup(func() { provisionedPublicKeyText = original })

	provisionedPublicKeyText = ""
	if _, err := ProvisionedPublicKey(); !errors.Is(err, ErrPublicKeyUnprovisioned) {
		t.Fatalf("unprovisioned error = %v", err)
	}

	publicKey := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	encoded, err := EncodePublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	provisionedPublicKeyText = string(bytes.TrimSuffix(encoded, []byte("\n")))
	got, err := ProvisionedPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, publicKey) {
		t.Fatalf("provisioned key mismatch: got %x want %x", got, publicKey)
	}

	provisionedPublicKeyText = "not-a-key"
	if _, err := ProvisionedPublicKey(); err == nil || errors.Is(err, ErrPublicKeyUnprovisioned) {
		t.Fatalf("malformed provisioned key error = %v", err)
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	publicKey := ed25519.PublicKey(bytes.Repeat([]byte{0x24}, ed25519.PublicKeySize))
	fingerprint, err := PublicKeyFingerprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint length = %d", len(fingerprint))
	}
	if fingerprint != "92a684adefd6ddaf253e72042460067e128440ee025e25d299fd581bc495b1ad" {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
}

package updateinfo

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestPublicKeyEncodingRoundTrip(t *testing.T) {
	publicKey := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	encoded, err := EncodePublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, publicKey) {
		t.Fatalf("decoded key mismatch: got %x want %x", decoded, publicKey)
	}
}

func TestDecodePublicKeyRejectsAlternateEncodings(t *testing.T) {
	publicKey := ed25519.PublicKey(bytes.Repeat([]byte{0x24}, ed25519.PublicKeySize))
	encoded, err := EncodePublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	canonical := string(bytes.TrimSuffix(encoded, []byte("\n")))

	cases := map[string]string{
		"empty":       "",
		"leading":     " " + canonical,
		"embedded lf": canonical[:10] + "\n" + canonical[10:],
		"padded":      canonical + "=",
		"trailing":    canonical + " \n",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePublicKey([]byte(value)); err == nil {
				t.Fatal("expected invalid public key encoding")
			}
		})
	}

	if _, err := DecodePublicKey([]byte(canonical + "\r\n")); err != nil {
		t.Fatalf("CRLF should be accepted: %v", err)
	}
}

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestParseLegacyPrivateKeyRequiresSinglePEMBlock(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshalLegacyPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(data)

	whitespace := append([]byte(" \t\n"), data...)
	whitespace = append(whitespace, []byte("\n\t ")...)
	if _, err := parseLegacyPrivateKey(whitespace); err != nil {
		t.Fatalf("surrounding whitespace rejected: %v", err)
	}

	cases := map[string][]byte{
		"leading text":  append([]byte("unexpected"), data...),
		"trailing text": append(append([]byte(nil), data...), []byte("unexpected")...),
		"second block":  append(append([]byte(nil), data...), data...),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLegacyPrivateKey(input); err == nil {
				t.Fatal("parseLegacyPrivateKey accepted material outside the PEM block")
			}
		})
	}
}

func TestLoadCertificateRequiresSinglePEMBlock(t *testing.T) {
	dir := t.TempDir()
	if _, err := Ensure(dir, "pem-strict-test"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.crt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	whitespace := append([]byte(" \t\n"), data...)
	whitespace = append(whitespace, []byte("\n\t ")...)
	if err := os.WriteFile(path, whitespace, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCertificate(path); err != nil {
		t.Fatalf("surrounding whitespace rejected: %v", err)
	}

	cases := map[string][]byte{
		"leading text":  append([]byte("unexpected"), data...),
		"trailing text": append(append([]byte(nil), data...), []byte("unexpected")...),
		"second block":  append(append([]byte(nil), data...), data...),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, input, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadCertificate(path); err == nil {
				t.Fatal("loadCertificate accepted material outside the PEM block")
			}
		})
	}
}

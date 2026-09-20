package identity

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Load reads an existing device identity without creating or renewing key or
// certificate material.
func Load(dir string) (*Identity, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("identity directory is required")
	}

	keyPath := filepath.Join(dir, "identity.key")
	certPath := filepath.Join(dir, "identity.crt")
	if err := requireRegularFile(keyPath, "identity private key"); err != nil {
		return nil, err
	}
	if err := requireRegularFile(certPath, "identity certificate"); err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read identity private key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid identity private key PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse identity private key: %w", err)
	}
	priv, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("identity key is not Ed25519")
	}
	pub := priv.Public().(ed25519.PublicKey)

	leaf, err := loadCertificate(certPath)
	if err != nil {
		return nil, err
	}
	certPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !certPub.Equal(pub) {
		return nil, errors.New("identity certificate does not match private key")
	}

	id := DeviceID(pub)
	if certID := CertificateDeviceID(leaf); certID != id {
		return nil, errors.New("identity certificate device ID does not match private key")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read identity certificate: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load TLS identity: %w", err)
	}
	cert.Leaf = leaf

	return &Identity{
		ID:          id,
		Name:        SanitizeName(leaf.Subject.CommonName),
		Certificate: cert,
		Leaf:        leaf,
		PublicKey:   pub,
		PrivateKey:  priv,
	}, nil
}

func requireRegularFile(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("load %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", label)
	}
	return nil
}

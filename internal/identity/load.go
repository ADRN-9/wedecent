package identity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Load reads an existing device identity without creating, migrating, or
// renewing key or certificate material.
func Load(dir string) (*Identity, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("identity directory is required")
	}

	certPath := filepath.Join(dir, "identity.crt")
	if err := requireRegularFile(certPath, "identity certificate"); err != nil {
		return nil, err
	}

	priv, err := loadExistingPrivateKey(dir)
	if err != nil {
		return nil, err
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

	cert := tlsCertificateFor(leaf, priv)
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

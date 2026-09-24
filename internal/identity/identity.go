package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const renewBefore = 30 * 24 * time.Hour

type Identity struct {
	ID          string
	Name        string
	Certificate tls.Certificate
	Leaf        *x509.Certificate
	PublicKey   ed25519.PublicKey
	PrivateKey  ed25519.PrivateKey
}

func Ensure(dir, name string) (*Identity, error) {
	return ensure(dir, name, defaultKeyProtectionScope())
}

func ensure(dir, name string, scope keyProtectionScope) (*Identity, error) {
	name = SanitizeName(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}
	certPath := filepath.Join(dir, "identity.crt")

	priv, err := loadOrCreatePrivateKey(dir, scope)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	id := DeviceID(pub)

	leaf, err := loadCertificate(certPath)
	certKeyMatches := false
	if err == nil {
		if certPub, ok := leaf.PublicKey.(ed25519.PublicKey); ok {
			certKeyMatches = certPub.Equal(pub)
		}
	}
	if err != nil || time.Until(leaf.NotAfter) < renewBefore || !certKeyMatches {
		leaf, err = issueCertificate(certPath, name, id, pub, priv)
		if err != nil {
			return nil, err
		}
	}
	cert := tlsCertificateFor(leaf, priv)
	return &Identity{ID: id, Name: name, Certificate: cert, Leaf: leaf, PublicKey: pub, PrivateKey: priv}, nil
}

func issueCertificate(path, name, id string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (*x509.Certificate, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	u, _ := url.Parse("wedecent://device/" + id)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(398 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid identity certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func DeviceID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:10])
	return "wd_" + strings.ToLower(enc)
}

func FingerprintPublicKey(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(der)
	return "SHA256:" + strings.ToUpper(hex.EncodeToString(h[:])), nil
}

func ParseFingerprint(s string) (string, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if strings.HasPrefix(s, "SHA256:") {
		s = strings.TrimPrefix(s, "SHA256:")
	}
	if len(s) != 64 {
		return "", errors.New("fingerprint must contain 64 hex characters")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", errors.New("fingerprint is not valid hex")
	}
	return "SHA256:" + s, nil
}

func CertificateDeviceID(cert *x509.Certificate) string {
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return DeviceID(pub)
}

func writePrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

func SanitizeName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 128 {
			break
		}
	}
	s = strings.TrimSpace(b.String())
	if s == "" {
		return "wedecent-device"
	}
	return s
}

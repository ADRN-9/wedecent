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
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	renewBefore                    = 30 * 24 * time.Hour
	maxIdentityCertificateFileSize = 64 << 10
)

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

	leaf, certErr := loadCertificate(certPath)
	if certErr != nil {
		leaf, err = issueCertificate(certPath, name, id, pub, priv, !errors.Is(certErr, os.ErrNotExist))
		if err != nil {
			return nil, err
		}
	} else {
		certPub, ok := leaf.PublicKey.(ed25519.PublicKey)
		certKeyMatches := ok && certPub.Equal(pub)
		if time.Until(leaf.NotAfter) < renewBefore || !certKeyMatches {
			leaf, err = issueCertificate(certPath, name, id, pub, priv, true)
			if err != nil {
				return nil, err
			}
		}
	}
	cert := tlsCertificateFor(leaf, priv)
	return &Identity{ID: id, Name: name, Certificate: cert, Leaf: leaf, PublicKey: pub, PrivateKey: priv}, nil
}

func issueCertificate(path, name, id string, pub ed25519.PublicKey, priv ed25519.PrivateKey, replaceExisting bool) (*x509.Certificate, error) {
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeCertificateFile(path, certPEM, replaceExisting); err != nil {
		if !replaceExisting && errors.Is(err, os.ErrExist) {
			existing, loadErr := loadCertificate(path)
			if loadErr != nil {
				return nil, fmt.Errorf("load concurrently created identity certificate: %w", loadErr)
			}
			existingPub, ok := existing.PublicKey.(ed25519.PublicKey)
			if !ok || !existingPub.Equal(pub) || time.Until(existing.NotAfter) < renewBefore {
				return nil, errors.New("concurrently created identity certificate is not valid for this identity")
			}
			return existing, nil
		}
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := readCertificateFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid identity certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, fmt.Errorf("invalid identity certificate self-signature: %w", err)
	}
	return cert, nil
}

func readCertificateFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat identity certificate path: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("identity certificate must be a regular file")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open identity certificate: %w", err)
	}
	defer f.Close()

	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened identity certificate: %w", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("re-stat identity certificate path: %w", err)
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errors.New("identity certificate path changed while opening")
	}

	data, err := io.ReadAll(io.LimitReader(f, maxIdentityCertificateFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read identity certificate: %w", err)
	}
	if len(data) > maxIdentityCertificateFileSize {
		return nil, errors.New("identity certificate file is too large")
	}
	return data, nil
}

func writeCertificateFile(path string, data []byte, replaceExisting bool) error {
	if !replaceExisting {
		return createCertificateFile(path, data)
	}

	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat identity certificate path before renewal: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.New("identity certificate must be a regular file")
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open identity certificate for renewal: %w", err)
	}
	defer f.Close()

	opened, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat opened identity certificate for renewal: %w", err)
	}
	afterOpen, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("re-stat identity certificate before renewal: %w", err)
	}
	if afterOpen.Mode()&os.ModeSymlink != 0 || !afterOpen.Mode().IsRegular() || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, afterOpen) {
		return errors.New("identity certificate path changed before renewal")
	}
	if err := f.Chmod(0o644); err != nil {
		return fmt.Errorf("set identity certificate permissions: %w", err)
	}
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("truncate identity certificate: %w", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("seek identity certificate: %w", err)
	}
	if err := writeAll(f, data); err != nil {
		return fmt.Errorf("write identity certificate: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync identity certificate: %w", err)
	}

	afterWrite, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("re-stat identity certificate after renewal: %w", err)
	}
	if afterWrite.Mode()&os.ModeSymlink != 0 || !afterWrite.Mode().IsRegular() || !os.SameFile(opened, afterWrite) {
		return errors.New("identity certificate path changed during renewal")
	}
	return nil
}

func createCertificateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create identity certificate: %w", err)
	}
	defer f.Close()
	if err := f.Chmod(0o644); err != nil {
		return fmt.Errorf("set identity certificate permissions: %w", err)
	}
	if err := writeAll(f, data); err != nil {
		return fmt.Errorf("write identity certificate: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync identity certificate: %w", err)
	}

	opened, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat created identity certificate: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat created identity certificate path: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !opened.Mode().IsRegular() || !os.SameFile(opened, pathInfo) {
		return errors.New("identity certificate path changed during creation")
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
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

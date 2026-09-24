package identity

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

const TerminalALPN = "wedecent/1"

func ServerTLS(id *Identity) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.Certificate},
		ClientAuth:   tls.RequestClientCert,
		NextProtos:   []string{TerminalALPN},
	}
}

// ClientTLS pins the peer's SubjectPublicKeyInfo fingerprint. The normal PKI
// verifier is intentionally bypassed because WeDecent devices use self-signed
// identities; pin verification replaces it.
func ClientTLS(id *Identity, expectedFingerprint string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{id.Certificate},
		InsecureSkipVerify: true, // Safe only with VerifyConnection below.
		NextProtos:         []string{TerminalALPN},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != TerminalALPN {
				return fmt.Errorf("peer did not negotiate %s", TerminalALPN)
			}
			if len(cs.PeerCertificates) != 1 {
				return errors.New("expected exactly one peer certificate")
			}
			if err := ValidatePeerCertificate(cs.PeerCertificates[0]); err != nil {
				return err
			}
			got, err := FingerprintPublicKey(cs.PeerCertificates[0].PublicKey)
			if err != nil {
				return err
			}
			want, err := ParseFingerprint(expectedFingerprint)
			if err != nil {
				return err
			}
			if got != want {
				return fmt.Errorf("device fingerprint mismatch: got %s", got)
			}
			return nil
		},
	}
}

func PeerCertificate(cs tls.ConnectionState) (*x509.Certificate, error) {
	if cs.NegotiatedProtocol != TerminalALPN {
		return nil, fmt.Errorf("peer did not negotiate %s", TerminalALPN)
	}
	if len(cs.PeerCertificates) != 1 {
		return nil, errors.New("peer did not present exactly one certificate")
	}
	if err := ValidatePeerCertificate(cs.PeerCertificates[0]); err != nil {
		return nil, err
	}
	return cs.PeerCertificates[0], nil
}

func ValidatePeerCertificate(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("peer certificate is outside its validity period")
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return errors.New("peer identity key is not Ed25519")
	}
	return nil
}

package portforward

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// NewPinnedCheckpointFenceHTTPClient creates a TLS-1.3-only client pinned to
// one exact DNS endpoint and its leaf SubjectPublicKeyInfo. Standard certificate
// chain and hostname verification remain enabled; the SPKI pin is additional.
func NewPinnedCheckpointFenceHTTPClient(hostname string, spkiSHA256 [sha256.Size]byte, roots *x509.CertPool) (*http.Client, error) {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" || len(hostname) > 253 || strings.ContainsAny(hostname, "/\\:@") ||
		net.ParseIP(hostname) != nil || spkiSHA256 == ([sha256.Size]byte{}) {
		return nil, ErrCheckpointIntegrity
	}
	for _, label := range strings.Split(hostname, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, ErrCheckpointIntegrity
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return nil, ErrCheckpointIntegrity
			}
		}
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: hostname,
		RootCAs: roots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrCheckpointIntegrity
			}
			actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if actual != spkiSHA256 {
				return errors.Join(ErrCheckpointIntegrity, errors.New("checkpoint authority SPKI pin mismatch"))
			}
			return nil
		},
	}
	transport := &http.Transport{
		TLSClientConfig: config,
		TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns: 4,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout: 30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}, nil
}

package portforward

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"testing"
)

func TestPinnedCheckpointFenceHTTPClientRequiresTLS13AndExactSPKI(t *testing.T) {
	spki := []byte("test subject public key info")
	pin := sha256.Sum256(spki)
	client, err := NewPinnedCheckpointFenceHTTPClient("witness-1.example.test", pin, x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("authority client must reject redirects: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected pinned HTTP transport")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "other.example:443"); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("authority transport dialed a different hostname: %v", err)
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "witness-1.example.test:80"); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("authority transport dialed a non-TLS port: %v", err)
	}
	config := transport.TLSClientConfig
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		config.ServerName != "witness-1.example.test" || config.InsecureSkipVerify {
		t.Fatalf("unexpected TLS policy: %+v", config)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{RawSubjectPublicKeyInfo: spki}}}
	if err := config.VerifyConnection(state); err != nil {
		t.Fatalf("matching SPKI pin rejected: %v", err)
	}
	state.PeerCertificates[0] = &x509.Certificate{RawSubjectPublicKeyInfo: []byte("different spki")}
	if err := config.VerifyConnection(state); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("mismatched SPKI pin accepted: %v", err)
	}
}

func TestPinnedCheckpointFenceHTTPClientRejectsAmbiguousEndpoint(t *testing.T) {
	pin := sha256.Sum256([]byte("pin"))
	for _, host := range []string{"", "127.0.0.1", "https://witness.example", "*.example.test", "witness.example:443", "witness..example"} {
		if _, err := NewPinnedCheckpointFenceHTTPClient(host, pin, nil); err == nil {
			t.Fatalf("ambiguous endpoint accepted: %q", host)
		}
	}
	if _, err := NewPinnedCheckpointFenceHTTPClient("witness.example", [sha256.Size]byte{}, nil); err == nil {
		t.Fatal("zero SPKI pin accepted")
	}
}

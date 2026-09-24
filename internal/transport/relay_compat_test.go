package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/relayproto"
)

func TestProtocolVersionCompatibilityRelayTLS(t *testing.T) {
	t.Parallel()

	certificate, caFile := relayCompatibilityCertificate(t)

	for _, tc := range []struct {
		name       string
		nextProtos []string
		wantOK     bool
	}{
		{name: "v1", nextProtos: []string{relayproto.ALPN}, wantOK: true},
		{name: "missing", nextProtos: nil},
		{name: "older", nextProtos: []string{"wedecent-relay/0"}},
		{name: "newer", nextProtos: []string{"wedecent-relay/2"}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			address, serverDone := serveRelayCompatibilityTLS(t, certificate, tc.nextProtos)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := dialRelayTLS(ctx, address, RelayOptions{
				CAFile:     caFile,
				ServerName: "localhost",
				Timeout:    2 * time.Second,
			})
			if tc.wantOK {
				if err != nil {
					t.Fatalf("dialRelayTLS(v1) error: %v", err)
				}
				if got := conn.ConnectionState().NegotiatedProtocol; got != relayproto.ALPN {
					t.Fatalf("negotiated protocol = %q, want %q", got, relayproto.ALPN)
				}
				_ = conn.Close()
			} else if err == nil {
				_ = conn.Close()
				t.Fatalf("dialRelayTLS(%q) unexpectedly succeeded", tc.name)
			}

			select {
			case <-serverDone:
			case <-ctx.Done():
				t.Fatal("relay compatibility server did not finish")
			}
		})
	}
}

func TestProtocolVersionCompatibilityRelayConstants(t *testing.T) {
	t.Parallel()

	if relayproto.ALPN != "wedecent-relay/1" {
		t.Fatalf("relay ALPN = %q, want wedecent-relay/1", relayproto.ALPN)
	}
	if got := string(relayproto.RegistrationBytes("challenge", "device")); got != "wedecent-relay-register-v1\x00challenge\x00device" {
		t.Fatalf("registration domain = %q", got)
	}
}

func relayCompatibilityCertificate(t *testing.T) (tls.Certificate, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	caFile := filepath.Join(t.TempDir(), "relay-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificate, caFile
}

func serveRelayCompatibilityTLS(t *testing.T, certificate tls.Certificate, nextProtos []string) (string, <-chan struct{}) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer listener.Close()
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			NextProtos:   nextProtos,
		})
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_ = conn.Handshake()
		_ = conn.Close()
	}()
	return listener.Addr().String(), done
}

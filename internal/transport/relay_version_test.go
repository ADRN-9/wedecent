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
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/relayproto"
)

func TestRelayTLSVersionCompatibility(t *testing.T) {
	cert, caPEM := relayTestCertificate(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		nextProtos []string
		wantErr    string
	}{
		{name: "v1 succeeds", nextProtos: []string{relayproto.ALPN}},
		{name: "unsupported v2 fails closed", nextProtos: []string{"wedecent-relay/2"}, wantErr: "relay TLS handshake"},
		{name: "missing ALPN fails closed", nextProtos: nil, wantErr: "relay ALPN mismatch"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			serverDone := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				server := tls.Server(raw, &tls.Config{
					MinVersion:   tls.VersionTLS13,
					Certificates: []tls.Certificate{cert},
					NextProtos:   tt.nextProtos,
				})
				defer server.Close()
				serverDone <- server.Handshake()
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialRelayTLS(ctx, listener.Addr().String(), RelayOptions{
				CAFile:     caPath,
				ServerName: "localhost",
				Timeout:    3 * time.Second,
			})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("relay v1 handshake: %v", err)
				}
				if conn.ConnectionState().NegotiatedProtocol != relayproto.ALPN {
					t.Fatalf("negotiated protocol = %q, want %q", conn.ConnectionState().NegotiatedProtocol, relayproto.ALPN)
				}
				_ = conn.Close()
			} else {
				if err == nil {
					_ = conn.Close()
					t.Fatalf("relay handshake unexpectedly succeeded; want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("relay handshake error = %v, want substring %q", err, tt.wantErr)
				}
			}

			select {
			case <-serverDone:
			case <-time.After(5 * time.Second):
				t.Fatal("relay TLS server handshake did not finish")
			}
		})
	}
}

func relayTestCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	now := time.Now()

	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "WeDecent relay test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}

	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, serverPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{serverDER, caDER},
		PrivateKey:  serverPrivate,
	}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

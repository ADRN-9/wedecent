package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/relayproto"
)

type relayReadStage struct {
	name   string
	waiter bool
	stage  string
}

func TestRelayProtocolReadStagesTimeoutAndCancel(t *testing.T) {
	stages := []relayReadStage{
		{name: "dial_challenge", stage: "challenge"},
		{name: "dial_ready", stage: "ready"},
		{name: "wait_challenge", waiter: true, stage: "challenge"},
		{name: "wait_waiting_ack", waiter: true, stage: "waiting"},
		{name: "wait_ready", waiter: true, stage: "ready"},
	}
	for _, stage := range stages {
		for _, cancel := range []bool{false, true} {
			name := stage.name + "/timeout"
			if cancel {
				name = stage.name + "/cancellation"
			}
			t.Run(name, func(t *testing.T) {
				runRelayReadStageCase(t, stage, cancel)
			})
		}
	}
}

func runRelayReadStageCase(t *testing.T, stage relayReadStage, cancel bool) {
	address, caFile, reached, release, serverDone := startRelayReadStageServer(t, stage)
	defer func() {
		close(release)
		<-serverDone
	}()

	ctx, cancelContext := context.WithCancel(context.Background())
	defer cancelContext()
	timeout := 45 * time.Millisecond
	if cancel {
		timeout = time.Hour
	}
	opts := RelayOptions{CAFile: caFile, ServerName: "127.0.0.1", Timeout: timeout}
	result := make(chan error, 1)
	go func() {
		if stage.waiter {
			_, err := WaitRelaySession(ctx, address, opts, testRelayIdentity(t))
			result <- err
			return
		}
		_, err := (RelayDialer{Address: address, TargetDeviceID: "wd_aaaaaaaaaaaaaaaa", Options: opts}).Dial(ctx)
		result <- err
	}()

	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not reach requested protocol read stage")
	}
	if cancel {
		cancelContext()
	}
	select {
	case err := <-result:
		if cancel {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("stage error = %v, want context.Canceled", err)
			}
		} else {
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Fatalf("stage error = %v, want network timeout", err)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay protocol read stage did not terminate")
	}
}

func testRelayIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &identity.Identity{ID: identity.DeviceID(pub), PublicKey: pub, PrivateKey: private}
}

func startRelayReadStageServer(t *testing.T, stage relayReadStage) (string, string, <-chan struct{}, chan struct{}, <-chan struct{}) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: func() *x509.CertPool {
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		return pool
	}(), DNSName: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caFile := filepath.Join(dir, "relay-ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reached := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer listener.Close()
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		conn := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{relayproto.ALPN}})
		if err := conn.Handshake(); err != nil {
			_ = conn.Close()
			return
		}
		if stage.stage == "challenge" {
			close(reached)
			<-release
			_ = conn.Close()
			return
		}
		if err := relayproto.Write(conn, relayproto.Message{Type: relayproto.TypeChallenge, Challenge: "challenge"}); err != nil {
			_ = conn.Close()
			return
		}
		request, err := relayproto.Read(conn)
		if err != nil {
			_ = conn.Close()
			return
		}
		want := relayproto.TypeConnect
		if stage.waiter {
			want = relayproto.TypeRegister
		}
		if request.Type != want {
			_ = conn.Close()
			return
		}
		if stage.waiter && stage.stage == "ready" {
			if err := relayproto.Write(conn, relayproto.Message{Type: relayproto.TypeWaiting}); err != nil {
				_ = conn.Close()
				return
			}
		}
		close(reached)
		<-release
		_ = conn.Close()
	}()
	return listener.Addr().String(), caFile, reached, release, done
}

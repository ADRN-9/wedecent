package session

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

type pipeDialer struct {
	server *identity.Identity
}

func (d pipeDialer) Dial(ctx context.Context, _ string) (transport.Conn, error) {
	clientSide, serverSide := net.Pipe()
	go func() {
		defer serverSide.Close()
		tlsServer := tls.Server(serverSide, identity.ServerTLS(d.server))
		_ = tlsServer.HandshakeContext(ctx)
	}()
	return clientSide, nil
}

func TestClientProbePinsTrustedFingerprint(t *testing.T) {
	clientID, err := identity.Ensure(t.TempDir(), "client")
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := identity.Ensure(t.TempDir(), "server")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := identity.FingerprintPublicKey(serverID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &Client{Identity: clientID, Dialer: pipeDialer{server: serverID}}
	if err := client.Probe(context.Background(), trust.Peer{Endpoint: "tcp://unused", Fingerprint: fp}); err != nil {
		t.Fatalf("Probe() rejected trusted server: %v", err)
	}
}

func TestClientProbeRejectsWrongFingerprint(t *testing.T) {
	clientID, err := identity.Ensure(t.TempDir(), "client")
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := identity.Ensure(t.TempDir(), "server")
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := identity.Ensure(t.TempDir(), "other")
	if err != nil {
		t.Fatal(err)
	}
	wrongFP, err := identity.FingerprintPublicKey(otherID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &Client{Identity: clientID, Dialer: pipeDialer{server: serverID}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Probe(ctx, trust.Peer{Endpoint: "tcp://unused", Fingerprint: wrongFP}); err == nil {
		t.Fatal("Probe() accepted the wrong server fingerprint")
	}
}

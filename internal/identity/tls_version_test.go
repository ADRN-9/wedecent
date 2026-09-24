package identity

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

type handshakeResult struct {
	state tls.ConnectionState
	err   error
}

func TestTerminalTLSVersionCompatibility(t *testing.T) {
	serverID, err := Ensure(t.TempDir(), "server")
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := Ensure(t.TempDir(), "client")
	if err != nil {
		t.Fatal(err)
	}
	serverFingerprint, err := FingerprintPublicKey(serverID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := ServerTLS(serverID)
	clientConfig := ClientTLS(clientID, serverFingerprint)
	if serverConfig.MinVersion != tls.VersionTLS13 || clientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("terminal TLS must require TLS 1.3")
	}
	if len(serverConfig.NextProtos) != 1 || serverConfig.NextProtos[0] != TerminalALPN {
		t.Fatalf("server ALPNs = %v, want only %q", serverConfig.NextProtos, TerminalALPN)
	}
	if len(clientConfig.NextProtos) != 1 || clientConfig.NextProtos[0] != TerminalALPN {
		t.Fatalf("client ALPNs = %v, want only %q", clientConfig.NextProtos, TerminalALPN)
	}

	t.Run("v1 succeeds", func(t *testing.T) {
		client, server := runTLSHandshake(t, clientConfig, serverConfig)
		if client.err != nil || server.err != nil {
			t.Fatalf("v1 handshake errors: client=%v server=%v", client.err, server.err)
		}
		if client.state.NegotiatedProtocol != TerminalALPN || server.state.NegotiatedProtocol != TerminalALPN {
			t.Fatalf("negotiated protocols: client=%q server=%q", client.state.NegotiatedProtocol, server.state.NegotiatedProtocol)
		}
	})

	t.Run("unsupported v2 fails closed", func(t *testing.T) {
		cfg := clientConfig.Clone()
		cfg.NextProtos = []string{"wedecent/2"}
		client, server := runTLSHandshake(t, cfg, serverConfig)
		if client.err == nil || server.err == nil {
			t.Fatalf("unsupported ALPN unexpectedly succeeded: client=%v server=%v", client.err, server.err)
		}
	})

	t.Run("missing ALPN fails closed", func(t *testing.T) {
		cfg := clientConfig.Clone()
		cfg.NextProtos = nil
		client, _ := runTLSHandshake(t, cfg, serverConfig)
		if client.err == nil {
			t.Fatal("missing ALPN unexpectedly succeeded")
		}
		if !strings.Contains(client.err.Error(), "did not negotiate "+TerminalALPN) {
			t.Fatalf("missing ALPN error = %v", client.err)
		}
	})
}

func runTLSHandshake(t *testing.T, clientConfig, serverConfig *tls.Config) (handshakeResult, handshakeResult) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := clientRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	clientConn := tls.Client(clientRaw, clientConfig.Clone())
	serverConn := tls.Server(serverRaw, serverConfig.Clone())
	defer clientConn.Close()
	defer serverConn.Close()

	serverCh := make(chan handshakeResult, 1)
	go func() {
		err := serverConn.Handshake()
		serverCh <- handshakeResult{state: serverConn.ConnectionState(), err: err}
	}()

	clientErr := clientConn.Handshake()
	client := handshakeResult{state: clientConn.ConnectionState(), err: clientErr}
	if clientErr != nil {
		_ = clientConn.Close()
	}
	server := <-serverCh
	return client, server
}

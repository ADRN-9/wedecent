package session

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

func pairingWireRequest(t *testing.T, server *Server, client *identity.Identity, serverFingerprint, secret, claimedID string) (protocol.Frame, error) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.ServeConn(serverSide)
	}()
	conn := tls.Client(clientSide, identity.ClientTLS(client, serverFingerprint))
	defer func() {
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("pairing server failed to exit")
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.HandshakeContext(context.Background()); err != nil {
		return protocol.Frame{}, err
	}
	payload, err := protocol.JSON(protocol.PairRequest{
		PairingSecret: secret, ClientID: claimedID, ClientName: "test-client",
	})
	if err != nil {
		return protocol.Frame{}, err
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePairRequest, Payload: payload}); err != nil {
		return protocol.Frame{}, err
	}
	return protocol.ReadFrame(conn)
}

func pairingErrorCode(t *testing.T, frame protocol.Frame) string {
	t.Helper()
	if frame.Type != protocol.TypeError {
		t.Fatalf("frame type %d is not an error", frame.Type)
	}
	var msg protocol.Error
	if err := protocol.ParseJSON(frame.Payload, &msg); err != nil {
		t.Fatal(err)
	}
	return msg.Code
}

func TestServerPairingAtomicIdentityAndAudit(t *testing.T) {
	serverIdentity, err := identity.Ensure(t.TempDir(), "server")
	if err != nil {
		t.Fatal(err)
	}
	first, err := identity.Ensure(t.TempDir(), "first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := identity.Ensure(t.TempDir(), "second")
	if err != nil {
		t.Fatal(err)
	}
	serverFP, err := identity.FingerprintPublicKey(serverIdentity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	store, err := trust.Open(filepath.Join(stateDir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Identity: serverIdentity, Trust: store, StateDir: stateDir}
	secret, err := trust.RotatePairingSecret(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong endpoint fingerprint cannot enter the authorized pairing path.
	if _, err := pairingWireRequest(t, server, first, "SHA256:"+strings.Repeat("0", 64), secret, first.ID); err == nil {
		t.Fatal("invalid endpoint fingerprint established a TLS session")
	}
	// A valid TLS client cannot claim another client's device ID.
	frame, err := pairingWireRequest(t, server, first, serverFP, secret, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if code := pairingErrorCode(t, frame); code != "pairing_denied" {
		t.Fatalf("mismatched client ID error = %q", code)
	}
	if _, ok := store.Get(first.ID); ok {
		t.Fatal("mismatched client ID was trusted")
	}
	if _, ok := store.Get(second.ID); ok {
		t.Fatal("claimed peer was trusted without proof")
	}

	frame, err = pairingWireRequest(t, server, first, serverFP, secret, first.ID)
	if err != nil || frame.Type != protocol.TypePairResponse {
		t.Fatalf("valid pairing response: type=%d err=%v", frame.Type, err)
	}
	frame, err = pairingWireRequest(t, server, second, serverFP, secret, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if code := pairingErrorCode(t, frame); code != "pairing_denied" {
		t.Fatalf("replayed pairing error = %q", code)
	}
	if _, ok := store.Get(second.ID); ok {
		t.Fatal("replayed client inserted into trusted clients")
	}
	if _, ok := store.Get(first.ID); !ok {
		t.Fatal("first authorized client missing from trust store")
	}

	f, err := os.Open(filepath.Join(stateDir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	successes, denied := 0, 0
	for scanner.Scan() {
		var ev audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		switch {
		case ev.Type == "pairing.trust_added" && ev.Outcome == "success":
			if ev.PeerID != first.ID {
				t.Fatalf("success audit names wrong peer: %+v", ev)
			}
			successes++
		case ev.Type == "pairing.request" && ev.Outcome == "denied":
			if ev.Reason != "client_identity_mismatch" && ev.Reason != "invalid_pairing_secret" {
				t.Fatalf("unexpected denial reason: %+v", ev)
			}
			denied++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if successes != 1 || denied != 2 {
		t.Fatalf("audit counts successes=%d denied=%d", successes, denied)
	}
}


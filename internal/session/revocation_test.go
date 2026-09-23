package session

import (
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

func TestServerObservesExternalClientRevocationForNewSession(t *testing.T) {
	serverID, err := identity.Ensure(t.TempDir(), "server")
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := identity.Ensure(t.TempDir(), "client")
	if err != nil {
		t.Fatal(err)
	}
	clientFingerprint, err := identity.FingerprintPublicKey(clientID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverFingerprint, err := identity.FingerprintPublicKey(serverID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	trustPath := filepath.Join(stateDir, "trusted-clients.json")
	store, err := trust.Open(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(trust.Peer{
		ID:          clientID.ID,
		Name:        clientID.Name,
		Fingerprint: clientFingerprint,
	}); err != nil {
		t.Fatal(err)
	}
	server := &Server{Identity: serverID, Trust: store, StateDir: stateDir}

	if code := openAuthorizedSessionError(t, server, clientID, serverFingerprint); code != "authorization_denied" {
		t.Fatalf("before revoke error = %q, want authorization_denied", code)
	}
	if _, err := trust.Revoke(trustPath, clientID.ID); err != nil {
		t.Fatal(err)
	}
	if code := openAuthorizedSessionError(t, server, clientID, serverFingerprint); code != "unauthorized" {
		t.Fatalf("after revoke error = %q, want unauthorized", code)
	}
}

func openAuthorizedSessionError(t *testing.T, server *Server, clientID *identity.Identity, serverFingerprint string) string {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	go server.ServeConn(serverSide)

	conn := tls.Client(clientSide, identity.ClientTLS(clientID, serverFingerprint))
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.JSON(protocol.OpenAuthorizedSession{})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeOpenAuthorizedSession, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.TypeError {
		t.Fatalf("response type = %d, want TypeError", frame.Type)
	}
	var protocolErr protocol.Error
	if err := protocol.ParseJSON(frame.Payload, &protocolErr); err != nil {
		t.Fatal(err)
	}
	return protocolErr.Code
}

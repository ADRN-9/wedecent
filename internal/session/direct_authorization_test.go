package session

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

type rejectingAuthorizer struct {
	clientID string
	targetID string
	grant    string
}

func (a *rejectingAuthorizer) Authorize(_ context.Context, clientID, targetID, grant string) error {
	a.clientID = clientID
	a.targetID = targetID
	a.grant = grant
	return errors.New("rejected for test")
}

func TestServeConnRejectsLegacyOpenSessionBeforePTY(t *testing.T) {
	server, clientConn, done := directSessionTestPair(t, nil)
	defer clientConn.Close()
	defer func() { <-done }()

	payload, _ := protocol.JSON(protocol.OpenSession{Cols: 80, Rows: 24, Term: "xterm"})
	if err := protocol.WriteFrame(clientConn, protocol.Frame{Type: protocol.TypeOpenSession, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.TypeError {
		t.Fatalf("frame type = %d", frame.Type)
	}
	var msg protocol.Error
	if err := protocol.ParseJSON(frame.Payload, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Code != "authorization_required" {
		t.Fatalf("error code = %q", msg.Code)
	}
	_ = server
}

func TestServeConnBindsAuthorizationToTLSClientIdentity(t *testing.T) {
	auth := &rejectingAuthorizer{}
	server, clientConn, done := directSessionTestPair(t, auth)
	defer clientConn.Close()
	defer func() { <-done }()

	payload, _ := protocol.JSON(protocol.OpenAuthorizedSession{
		Cols: 80, Rows: 24, Term: "xterm", ConnectionGrant: "header.payload.signature",
	})
	if err := protocol.WriteFrame(clientConn, protocol.Frame{Type: protocol.TypeOpenAuthorizedSession, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.TypeError {
		t.Fatalf("frame type = %d", frame.Type)
	}
	var msg protocol.Error
	if err := protocol.ParseJSON(frame.Payload, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Code != "authorization_denied" {
		t.Fatalf("error code = %q", msg.Code)
	}
	if auth.clientID == "" || auth.targetID != server.Identity.ID || auth.grant != "header.payload.signature" {
		t.Fatalf("authorization inputs = client:%q target:%q grant:%q", auth.clientID, auth.targetID, auth.grant)
	}
}

func TestServeConnRejectsAuthorizedSessionWithoutAuthorizer(t *testing.T) {
	_, clientConn, done := directSessionTestPair(t, nil)
	defer clientConn.Close()
	defer func() { <-done }()

	payload, _ := protocol.JSON(protocol.OpenAuthorizedSession{
		Cols: 80, Rows: 24, Term: "xterm", ConnectionGrant: "header.payload.signature",
	})
	if err := protocol.WriteFrame(clientConn, protocol.Frame{Type: protocol.TypeOpenAuthorizedSession, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	var msg protocol.Error
	if err := protocol.ParseJSON(frame.Payload, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Code != "authorization_unavailable" {
		t.Fatalf("error code = %q", msg.Code)
	}
}

func directSessionTestPair(t *testing.T, auth DirectAuthorizer) (*Server, *tls.Conn, <-chan struct{}) {
	t.Helper()
	serverID, err := identity.Ensure(t.TempDir(), "server")
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := identity.Ensure(t.TempDir(), "client")
	if err != nil {
		t.Fatal(err)
	}
	store, err := trust.Open(t.TempDir() + "/trusted-clients.json")
	if err != nil {
		t.Fatal(err)
	}
	clientFP, err := identity.FingerprintPublicKey(clientID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(trust.Peer{ID: clientID.ID, Name: clientID.Name, Fingerprint: clientFP}); err != nil {
		t.Fatal(err)
	}
	serverFP, err := identity.FingerprintPublicKey(serverID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{Identity: serverID, Trust: store, DirectAuthorizer: auth}
	clientSide, serverSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.ServeConn(serverSide)
	}()

	clientConn := tls.Client(clientSide, identity.ClientTLS(clientID, serverFP))
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := clientConn.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetDeadline(time.Time{})
	return server, clientConn, done
}

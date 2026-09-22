package session

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

type acceptingConnectionAuthorizer struct {
	clientID string
	targetID string
	grant    string
	calls    int
}

func (a *acceptingConnectionAuthorizer) Authorize(_ context.Context, clientID, targetID, grant string) error {
	a.clientID = clientID
	a.targetID = targetID
	a.grant = grant
	a.calls++
	return nil
}

type singleConnectionDialer struct {
	conn transport.Conn
}

func (d *singleConnectionDialer) Dial(context.Context, string) (transport.Conn, error) {
	return d.conn, nil
}

func TestServeConnRejectsGrantFreeConnectionOpen(t *testing.T) {
	_, clientConn, done := directSessionTestPair(t, &acceptingConnectionAuthorizer{})
	defer clientConn.Close()
	defer func() { <-done }()

	if err := protocol.WriteFrame(clientConn, protocol.Frame{Type: protocol.TypeOpenConnection}); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.TypeError {
		t.Fatalf("frame type = %d, want error", frame.Type)
	}
	var msg protocol.Error
	if err := protocol.ParseJSON(frame.Payload, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Code != "authorization_required" {
		t.Fatalf("error code = %q", msg.Code)
	}
}

func TestServeConnAuthorizedConnectionBindsGrantAndCloses(t *testing.T) {
	auth := &acceptingConnectionAuthorizer{}
	server, clientConn, done := directSessionTestPair(t, auth)
	defer clientConn.Close()

	payload, err := protocol.JSON(protocol.OpenAuthorizedConnection{ConnectionGrant: "header.payload.signature"})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(clientConn, protocol.Frame{Type: protocol.TypeOpenAuthorizedConnection, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.TypeConnectionAccepted {
		t.Fatalf("frame type = %d, want connection accepted", frame.Type)
	}
	if auth.calls != 1 || auth.clientID == "" || auth.targetID != server.Identity.ID || auth.grant != "header.payload.signature" {
		t.Fatalf("authorization inputs = calls:%d client:%q target:%q grant:%q", auth.calls, auth.clientID, auth.targetID, auth.grant)
	}

	if err := protocol.WriteFrame(clientConn, protocol.Frame{Type: protocol.TypePing}); err != nil {
		t.Fatal(err)
	}
	frame, err = protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.TypePong {
		t.Fatalf("frame type = %d, want pong", frame.Type)
	}

	if err := protocol.WriteFrame(clientConn, protocol.Frame{Type: protocol.TypeClose}); err != nil {
		t.Fatal(err)
	}
	frame, err = protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.TypeClose {
		t.Fatalf("frame type = %d, want close", frame.Type)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not close authorized connection")
	}
}

func TestClientOpenConnectionDirectAuthorizesAndObservesRemoteClose(t *testing.T) {
	client, server, serverSide, serverDone, auth, peer := newOpenConnectionTestPair(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connection, err := client.OpenConnection(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	if auth.calls != 1 || auth.clientID != client.Identity.ID || auth.targetID != server.Identity.ID || auth.grant != "header.payload.signature" {
		t.Fatalf("authorization inputs = calls:%d client:%q target:%q grant:%q", auth.calls, auth.clientID, auth.targetID, auth.grant)
	}
	select {
	case <-connection.Done():
		t.Fatal("connection closed before peer shutdown")
	default:
	}

	if err := serverSide.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client did not observe remote close")
	}
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not exit after remote close")
	}
}

func TestClientOpenConnectionWebRelayUsesGrantFreeInnerOpen(t *testing.T) {
	client, _, _, serverDone, auth, peer := newOpenConnectionTestPair(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connection, err := client.OpenConnection(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	if auth.calls != 0 {
		t.Fatalf("direct authorizer calls = %d, want 0 for web relay inner session", auth.calls)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client connection did not close")
	}
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("parked relay server did not exit")
	}
}

func newOpenConnectionTestPair(t *testing.T, parkedRelay bool) (*Client, *Server, net.Conn, <-chan struct{}, *acceptingConnectionAuthorizer, trust.Peer) {
	t.Helper()
	serverID, err := identity.Ensure(t.TempDir(), "server")
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := identity.Ensure(t.TempDir(), "client")
	if err != nil {
		t.Fatal(err)
	}
	serverTrust, err := trust.Open(filepath.Join(t.TempDir(), "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	clientFP, err := identity.FingerprintPublicKey(clientID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverTrust.Put(trust.Peer{ID: clientID.ID, Name: clientID.Name, Fingerprint: clientFP}); err != nil {
		t.Fatal(err)
	}
	serverFP, err := identity.FingerprintPublicKey(serverID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	auth := &acceptingConnectionAuthorizer{}
	server := &Server{Identity: serverID, Trust: serverTrust, DirectAuthorizer: auth}
	clientSide, serverSide := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if parkedRelay {
			server.ServeParkedRelayConn(serverSide)
			return
		}
		server.ServeConn(serverSide)
	}()

	endpoint := "tcp://test.invalid:7443"
	if parkedRelay {
		endpoint = "wsrelay://relay.test/" + serverID.ID
	}
	client := &Client{
		Identity:        clientID,
		Dialer:          &singleConnectionDialer{conn: clientSide},
		ConnectionGrant: "header.payload.signature",
	}
	peer := trust.Peer{ID: serverID.ID, Name: serverID.Name, Fingerprint: serverFP, Endpoint: endpoint}
	return client, server, serverSide, serverDone, auth, peer
}

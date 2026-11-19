package session

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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
	grant := testConnectionGrant()
	server, clientConn, done := directSessionTestPair(t, auth)
	defer clientConn.Close()
	defer func() { <-done }()

	payload, _ := protocol.JSON(protocol.OpenAuthorizedSession{
		Cols: 80, Rows: 24, Term: "xterm", ConnectionGrant: grant,
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
	if auth.clientID == "" || auth.targetID != server.Identity.ID || auth.grant != grant {
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

type evidenceTrackingAuthorizer struct {
	clientID string
	targetID string
	jti string
	flow string
	verifyErr error
}

func (a *evidenceTrackingAuthorizer) Authorize(_ context.Context, clientID, targetID, _ string) error {
	a.clientID, a.targetID = clientID, targetID
	return nil
}

func (a *evidenceTrackingAuthorizer) VerifyConsumption(_ context.Context, clientID, targetID, jti, flow string) error {
	a.clientID, a.targetID, a.jti, a.flow = clientID, targetID, jti, flow
	return a.verifyErr
}

func TestTerminalSessionsRequireIndependentServerGrantEvidence(t *testing.T) {
	for _, flow := range []string{"direct", "relay"} {
		t.Run(flow, func(t *testing.T) {
			auth := &evidenceTrackingAuthorizer{verifyErr: errors.New("grant evidence unavailable")}
			var server *Server
			var clientConn *tls.Conn
			var done <-chan struct{}
			if flow == "relay" {
				server, clientConn, done = relaySessionTestPair(t, auth)
			} else {
				server, clientConn, done = directSessionTestPair(t, auth)
			}
			defer clientConn.Close()
			defer func() { <-done }()

			var frame protocol.Frame
			if flow == "relay" {
				payload, _ := protocol.JSON(protocol.OpenSession{Cols: 80, Rows: 24, Term: "xterm", GrantJTI: "76b4c468-4e39-437c-a9c8-b758c92ab89b"})
				frame = protocol.Frame{Type: protocol.TypeOpenSession, Payload: payload}
			} else {
				payload, _ := protocol.JSON(protocol.OpenAuthorizedSession{Cols: 80, Rows: 24, Term: "xterm", ConnectionGrant: testConnectionGrant()})
				frame = protocol.Frame{Type: protocol.TypeOpenAuthorizedSession, Payload: payload}
			}
			if err := protocol.WriteFrame(clientConn, frame); err != nil {
				t.Fatal(err)
			}
			response, err := protocol.ReadFrame(clientConn)
			if err != nil {
				t.Fatal(err)
			}
			var msg protocol.Error
			if response.Type != protocol.TypeError || protocol.ParseJSON(response.Payload, &msg) != nil || msg.Code != "authorization_denied" {
				t.Fatalf("response = %#v, error = %#v", response, msg)
			}
			if auth.clientID == "" || auth.targetID != server.Identity.ID ||
				auth.jti != "76b4c468-4e39-437c-a9c8-b758c92ab89b" || auth.flow != flow {
				t.Fatalf("evidence verification inputs = %#v", auth)
			}
		})
	}
}

func testConnectionGrant() string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"76b4c468-4e39-437c-a9c8-b758c92ab89b"}`))
	return "header." + payload + ".signature"
}

func directSessionTestPair(t *testing.T, auth DirectAuthorizer) (*Server, *tls.Conn, <-chan struct{}) {
	return sessionTestPair(t, auth, false)
}

func relaySessionTestPair(t *testing.T, auth DirectAuthorizer) (*Server, *tls.Conn, <-chan struct{}) {
	return sessionTestPair(t, auth, true)
}

func sessionTestPair(t *testing.T, auth DirectAuthorizer, relay bool) (*Server, *tls.Conn, <-chan struct{}) {
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
		if relay {
			server.ServeParkedRelayConn(serverSide)
		} else {
			server.ServeConn(serverSide)
		}
	}()

	clientConn := tls.Client(clientSide, identity.ClientTLS(clientID, serverFP))
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := clientConn.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetDeadline(time.Time{})
	return server, clientConn, done
}

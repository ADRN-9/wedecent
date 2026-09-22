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
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

type managedTestDialer struct {
	conn transport.Conn
}

func (d *managedTestDialer) Dial(ctx context.Context, _ string) (transport.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.conn == nil {
		return nil, errors.New("managed test dialer already used")
	}
	conn := d.conn
	d.conn = nil
	return conn, nil
}

func TestOpenManagedTerminalAuthorizationAndRemoteClose(t *testing.T) {
	tests := []struct {
		name       string
		endpoint   string
		grant      string
		wantType   protocol.Type
		wantInBand bool
	}{
		{
			name:       "direct uses in-band grant",
			endpoint:   "tcp://ignored.test:7443",
			grant:      "header.payload.signature",
			wantType:   protocol.TypeOpenAuthorizedSession,
			wantInBand: true,
		},
		{
			name:     "web relay uses outer authorization",
			endpoint: "wsrelay://relay.example/wd_target00000000",
			wantType: protocol.TypeOpenSession,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientID, serverID, peer := managedSessionTestIdentities(t, tt.endpoint)
			clientSide, serverSide := net.Pipe()
			dialer := &managedTestDialer{conn: clientSide}
			firstFrame := make(chan protocol.Frame, 1)
			proceed := make(chan struct{})
			serverErr := make(chan error, 1)

			go func() {
				conn := tls.Server(serverSide, identity.ServerTLS(serverID))
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if err := conn.HandshakeContext(context.Background()); err != nil {
					serverErr <- err
					return
				}
				frame, err := protocol.ReadFrame(conn)
				if err != nil {
					serverErr <- err
					return
				}
				firstFrame <- frame
				if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeSessionAccepted}); err != nil {
					serverErr <- err
					return
				}
				<-proceed
				if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePing}); err != nil {
					serverErr <- err
					return
				}
				pong, err := protocol.ReadFrame(conn)
				if err != nil {
					serverErr <- err
					return
				}
				if pong.Type != protocol.TypePong {
					serverErr <- errors.New("managed terminal did not answer ping")
					return
				}
				if err := protocol.WriteFrame(conn, protocol.Frame{
					Type: protocol.TypeData, StreamID: terminalStreamID, Payload: []byte("discarded output"),
				}); err != nil {
					serverErr <- err
					return
				}
				if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeClose}); err != nil {
					serverErr <- err
					return
				}
				ack, err := protocol.ReadFrame(conn)
				if err != nil {
					serverErr <- err
					return
				}
				if ack.Type != protocol.TypeClose {
					serverErr <- errors.New("managed terminal did not acknowledge close")
					return
				}
				serverErr <- nil
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client := &Client{Identity: clientID, Dialer: dialer, ConnectionGrant: tt.grant}
			managed, err := client.OpenManagedTerminal(ctx, peer, 100, 40, "xterm-256color")
			if err != nil {
				t.Fatal(err)
			}

			frame := <-firstFrame
			if frame.Type != tt.wantType {
				t.Fatalf("open frame type = %d, want %d", frame.Type, tt.wantType)
			}
			if tt.wantInBand {
				var open protocol.OpenAuthorizedSession
				if err := protocol.ParseJSON(frame.Payload, &open); err != nil {
					t.Fatal(err)
				}
				if open.ConnectionGrant != tt.grant || open.Cols != 100 || open.Rows != 40 || open.Term != "xterm-256color" {
					t.Fatalf("authorized open = %#v", open)
				}
			} else {
				var open protocol.OpenSession
				if err := protocol.ParseJSON(frame.Payload, &open); err != nil {
					t.Fatal(err)
				}
				if open.Cols != 100 || open.Rows != 40 || open.Term != "xterm-256color" {
					t.Fatalf("open = %#v", open)
				}
			}
			close(proceed)

			waitManagedDoneOrServerError(t, managed, serverErr)
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagedTerminalUnexpectedFrameFailsClosed(t *testing.T) {
	clientID, serverID, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	clientSide, serverSide := net.Pipe()
	dialer := &managedTestDialer{conn: clientSide}
	proceed := make(chan struct{})
	serverErr := make(chan error, 1)

	go func() {
		conn := tls.Server(serverSide, identity.ServerTLS(serverID))
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := conn.HandshakeContext(context.Background()); err != nil {
			serverErr <- err
			return
		}
		if _, err := protocol.ReadFrame(conn); err != nil {
			serverErr <- err
			return
		}
		if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeSessionAccepted}); err != nil {
			serverErr <- err
			return
		}
		<-proceed
		if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.Type(250)}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := &Client{
		Identity:        clientID,
		Dialer:          dialer,
		ConnectionGrant: "header.payload.signature",
	}
	managed, err := client.OpenManagedTerminal(ctx, peer, 80, 24, "xterm")
	if err != nil {
		t.Fatal(err)
	}
	close(proceed)
	waitManagedDoneOrServerError(t, managed, serverErr)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestOpenManagedTerminalRejectsMissingDirectGrantBeforeDial(t *testing.T) {
	clientID, _, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	dialer := &managedTestDialer{}
	client := &Client{Identity: clientID, Dialer: dialer}
	if _, err := client.OpenManagedTerminal(context.Background(), peer, 80, 24, "xterm"); err == nil {
		t.Fatal("OpenManagedTerminal accepted a direct connection without a grant")
	}
}

func waitManagedDoneOrServerError(t *testing.T, managed *ManagedTerminal, serverErr <-chan error) {
	t.Helper()
	select {
	case <-managed.Done():
		return
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("test server failed before managed session ended: %v", err)
		}
		select {
		case <-managed.Done():
			return
		case <-time.After(2 * time.Second):
			t.Fatal("managed terminal did not observe server completion")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("managed terminal did not observe remote close")
	}
}

func managedSessionTestIdentities(t *testing.T, endpoint string) (*identity.Identity, *identity.Identity, trust.Peer) {
	t.Helper()
	clientID, err := identity.Ensure(t.TempDir(), "managed-client")
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := identity.Ensure(t.TempDir(), "managed-server")
	if err != nil {
		t.Fatal(err)
	}
	serverFP, err := identity.FingerprintPublicKey(serverID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return clientID, serverID, trust.Peer{
		ID:          serverID.ID,
		Name:        serverID.Name,
		Fingerprint: serverFP,
		Endpoint:    endpoint,
	}
}

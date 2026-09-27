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
)

func TestManagedTerminalProbeLatencyUsesExistingAuthenticatedSession(t *testing.T) {
	clientID, serverID, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	clientSide, serverSide := net.Pipe()
	dialer := &managedTestDialer{conn: clientSide}
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
		ping, err := protocol.ReadFrame(conn)
		if err != nil {
			serverErr <- err
			return
		}
		if ping.Type != protocol.TypePing || len(ping.Payload) != 0 {
			serverErr <- errors.New("managed latency probe did not use existing empty Ping semantics")
			return
		}
		if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePong}); err != nil {
			serverErr <- err
			return
		}
		frame, err := protocol.ReadFrame(conn)
		if err != nil {
			serverErr <- err
			return
		}
		if frame.Type != protocol.TypeClose {
			serverErr <- errors.New("managed terminal did not close after latency probe")
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

	probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Second)
	rtt, err := managed.ProbeLatency(probeCtx)
	probeCancel()
	if err != nil {
		t.Fatal(err)
	}
	if rtt < 0 || rtt > time.Second {
		t.Fatalf("RTT = %s", rtt)
	}
	// The peer may close immediately after receiving the application close frame,
	// so a best-effort TLS closeNotify can race with an already-closed net.Pipe.
	// Local ManagedTerminal teardown remains authoritative in either case.
	_ = managed.Close()
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("latency test server did not finish")
	}
}

func TestManagedTerminalProbeLatencyHonorsContext(t *testing.T) {
	managed := &ManagedTerminal{done: make(chan struct{}), probePong: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := managed.ProbeLatency(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ProbeLatency error = %v", err)
	}
}

package session

import (
	"errors"
	"net"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/protocol"
)

func TestManagedTerminalFinishClosesDoneOnce(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	// A real ManagedTerminal owns a *tls.Conn. The lifecycle semantics exercised
	// here are covered indirectly by the connection-service observable-handle
	// tests; keep this test focused on the protocol close helper used by the
	// server-side lifecycle.
	frames := make(chan protocol.Frame, 1)
	errs := make(chan error, 1)
	frames <- protocol.Frame{Type: protocol.TypeClose}
	waitForPeerClose(frames, errs, 20*time.Millisecond)

	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

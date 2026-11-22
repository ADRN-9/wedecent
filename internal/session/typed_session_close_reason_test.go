package session

import (
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
)

func TestTypedSessionCloseReasonTerminalReadBeforeRevocation(t *testing.T) {
	closeReason := newTypedSessionCloseReason("connection_ended")
	closeReason.set("peer_disconnect")

	active := &activeTerminalSession{}
	if !active.beginTermination("client_revoked") {
		t.Fatal("revocation did not claim the terminal session")
	}
	assertTypedSessionCloseReason(t, active, closeReason, "client_revoked")
}

func TestTypedSessionCloseReasonRevocationBeforeTerminalReadCompletion(t *testing.T) {
	closeReason := newTypedSessionCloseReason("connection_ended")
	active := &activeTerminalSession{}
	if !active.beginTermination("client_revoked") {
		t.Fatal("revocation did not claim the terminal session")
	}

	closeReason.set(active.reasonOr("peer_disconnect"))
	assertTypedSessionCloseReason(t, active, closeReason, "client_revoked")
}

func TestTypedSessionCloseReasonConcurrentReadCompletionAndAsyncRevocationCleanup(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("typed-close-reason-race")
	closeReason := newTypedSessionCloseReason("connection_ended")
	auditEvents := make(chan audit.Event, 4)
	tracker := newTypedTerminalAuditTracker(client.ID, string(TransportDirectTCP), func(event audit.Event) {
		auditEvents <- event
	}, "00000000-0000-4000-8000-000000000021")
	tracker.opened(2)
	<-auditEvents

	active := &activeTerminalSession{
		server: rig.server, ID: "00000000-0000-4000-8000-000000000021",
		clientID: client.ID, transport: string(TransportDirectTCP),
		cleanupReady: make(chan struct{}), terminationDone: make(chan struct{}),
	}
	cleanupStarted := make(chan struct{})
	start := make(chan struct{})
	cleanupFinished := make(chan struct{})
	cleanupReason := make(chan string, 1)
	if err := active.setCleanup(func() error {
		close(cleanupStarted)
		<-start
		reason := resolveTypedSessionCloseReason(active, closeReason)
		tracker.closeAll(reason)
		cleanupReason <- reason
		close(cleanupFinished)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	active.terminateAsync("client_revoked")
	select {
	case <-cleanupStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("asynchronous revocation cleanup did not reach its barrier")
	}

	readReady := make(chan struct{})
	readFinished := make(chan struct{})
	go func() {
		close(readReady)
		<-start
		closeReason.set(active.reasonOr("peer_disconnect"))
		close(readFinished)
	}()
	select {
	case <-readReady:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal read-completion path did not reach its barrier")
	}

	// Both operations are parked at the barrier before either touches the
	// shared close-reason state.
	close(start)
	select {
	case <-readFinished:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal read-completion path did not finish")
	}
	select {
	case <-cleanupFinished:
	case <-time.After(3 * time.Second):
		t.Fatal("asynchronous cleanup did not finish")
	}
	select {
	case reason := <-cleanupReason:
		if reason != "client_revoked" {
			t.Fatalf("cleanup selected reason %q, want client_revoked", reason)
		}
	default:
		t.Fatal("cleanup did not report its selected reason")
	}

	if err := active.finish(); err != nil {
		t.Fatalf("finish after asynchronous revocation cleanup: %v", err)
	}
	select {
	case event := <-auditEvents:
		if event.Type != "terminal.stream_closed" || event.StreamID != 2 || event.Reason != "client_revoked" {
			t.Fatalf("typed stream close audit = %#v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("asynchronous cleanup did not emit the typed stream close audit")
	}

	closedEvent := typedSessionClosedAuditEvent(
		client.ID, active.ID, string(TransportDirectTCP),
		resolveTypedSessionCloseReason(active, closeReason), nil,
	)
	if err := rig.server.recordGrantAudit(TransportMetadata{Kind: TransportDirectTCP}, closedEvent, nil); err != nil {
		t.Fatalf("record terminal.session_closed audit: %v", err)
	}

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		terminated, closed := false, false
		for _, event := range events {
			if event.SessionID != active.ID || event.PeerID != client.ID || event.Reason != "client_revoked" {
				continue
			}
			terminated = terminated || event.Type == "terminal.session_terminated"
			closed = closed || event.Type == "terminal.session_closed"
		}
		return terminated && closed
	})
	foundTermination, foundSessionClosed := false, false
	for _, event := range events {
		if event.SessionID != active.ID || event.PeerID != client.ID {
			continue
		}
		switch event.Type {
		case "terminal.session_terminated":
			if event.Outcome != "success" || event.Reason != "client_revoked" {
				t.Fatalf("session termination audit = %#v", event)
			}
			foundTermination = true
		case "terminal.session_closed":
			if event.Outcome != "success" || event.Reason != "client_revoked" {
				t.Fatalf("terminal.session_closed audit = %#v", event)
			}
			foundSessionClosed = true
		}
	}
	if !foundTermination {
		t.Fatal("session termination audit did not preserve the revocation reason")
	}
	if !foundSessionClosed {
		t.Fatal("terminal.session_closed audit did not preserve the revocation reason")
	}
	assertTypedSessionCloseReason(t, active, closeReason, "client_revoked")
}

func assertTypedSessionCloseReason(t *testing.T, active *activeTerminalSession, closeReason *typedSessionCloseReason, want string) {
	t.Helper()
	if got := resolveTypedSessionCloseReason(active, closeReason); got != want {
		t.Fatalf("final terminal session close reason = %q, want %q", got, want)
	}
}

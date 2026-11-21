package session

import (
	"runtime"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
)

func TestTypedSessionCloseReasonConcurrentReadCompletionAndAsyncRevocationCleanup(t *testing.T) {
	for i := 0; i < 50; i++ {
		t.Run("iteration", func(t *testing.T) {
			runTypedSessionCloseReasonRace(t)
		})
	}
}

func runTypedSessionCloseReasonRace(t *testing.T) {
	t.Helper()
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
	startRace := make(chan struct{})
	cleanupFinished := make(chan struct{})
	releaseCleanup := make(chan struct{})
	if err := active.setCleanup(func() error {
		close(cleanupStarted)
		<-startRace
		for i := 0; i < 4096; i++ {
			_ = resolveTypedSessionCloseReason(active, closeReason)
			runtime.Gosched()
		}
		tracker.closeAll(resolveTypedSessionCloseReason(active, closeReason))
		close(cleanupFinished)
		<-releaseCleanup
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	active.terminateAsync("client_revoked")
	select {
	case <-cleanupStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("asynchronous revocation cleanup did not start")
	}

	readCompletion := make(chan struct{})
	go func() {
		<-startRace
		for i := 0; i < 4096; i++ {
			closeReason.set(active.reasonOr("peer_disconnect"))
			runtime.Gosched()
		}
		close(readCompletion)
	}()
	close(startRace)

	select {
	case <-readCompletion:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal read-completion path did not finish")
	}
	select {
	case <-cleanupFinished:
	case <-time.After(3 * time.Second):
		t.Fatal("asynchronous cleanup did not finish its close-reason reads")
	}
	finishDone := make(chan error, 1)
	go func() { finishDone <- active.finish() }()
	finishWaiting := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		active.mu.Lock()
		finishWaiting = active.finished
		active.mu.Unlock()
		if finishWaiting {
			break
		}
		runtime.Gosched()
	}
	if !finishWaiting {
		t.Fatal("terminal handler finish did not enter its termination wait")
	}
	select {
	case err := <-finishDone:
		t.Fatalf("terminal handler finish returned before asynchronous cleanup: %v", err)
	default:
	}
	close(releaseCleanup)
	select {
	case <-active.terminationDone:
	case <-time.After(3 * time.Second):
		t.Fatal("asynchronous revocation termination did not finish")
	}
	select {
	case err := <-finishDone:
		if err != nil {
			t.Fatalf("finish after revocation cleanup: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("terminal handler finish did not complete after asynchronous cleanup")
	}

	var streamClosed bool
	select {
	case event := <-auditEvents:
		streamClosed = event.Type == "terminal.stream_closed" && event.StreamID == 2 && event.Reason == "client_revoked"
	case <-time.After(3 * time.Second):
		t.Fatal("asynchronous cleanup did not emit the typed stream close audit")
	}

	var sessionTerminated bool
	for _, event := range waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		for _, event := range events {
			if event.SessionID == active.ID && event.Type == "terminal.session_terminated" && event.Reason == "client_revoked" {
				return true
			}
		}
		return false
	}) {
		if event.SessionID == active.ID && event.Type == "terminal.session_terminated" && event.Reason == "client_revoked" {
			sessionTerminated = true
		}
	}
	if !sessionTerminated || !streamClosed {
		t.Fatalf("revocation audit outcomes: sessionTerminated=%v streamClosed=%v", sessionTerminated, streamClosed)
	}
}

package session

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/protocol"
)

type fakeTypedPTY struct {
	mu             sync.Mutex
	written        bytes.Buffer
	cols           uint16
	rows           uint16
	resizeErr      error
	writeErr       error
	closed         chan struct{}
	closeOne       sync.Once
	closeErr       error
	closeStarted   chan struct{}
	closeRelease   chan struct{}
	closeStartOnce sync.Once
}

func newFakeTypedPTY() *fakeTypedPTY             { return &fakeTypedPTY{closed: make(chan struct{})} }
func (p *fakeTypedPTY) Read([]byte) (int, error) { <-p.closed; return 0, io.EOF }
func (p *fakeTypedPTY) Wait() error              { <-p.closed; return nil }
func (p *fakeTypedPTY) Close() error {
	p.closeOne.Do(func() {
		if p.closeStarted != nil {
			p.closeStartOnce.Do(func() { close(p.closeStarted) })
		}
		if p.closeRelease != nil {
			<-p.closeRelease
		}
		close(p.closed)
	})
	return p.closeErr
}
func (p *fakeTypedPTY) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.writeErr != nil {
		return 0, p.writeErr
	}
	return p.written.Write(data)
}
func (p *fakeTypedPTY) Resize(cols, rows uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resizeErr != nil {
		return p.resizeErr
	}
	p.cols, p.rows = cols, rows
	return nil
}
func (p *fakeTypedPTY) snapshot() (string, uint16, uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.written.String(), p.cols, p.rows
}

type typedFrameSink struct {
	mu     sync.Mutex
	frames []protocol.Frame
}

func (s *typedFrameSink) write(frame protocol.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	frame.Payload = append([]byte(nil), frame.Payload...)
	s.frames = append(s.frames, frame)
	return nil
}
func (s *typedFrameSink) snapshot() []protocol.Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]protocol.Frame(nil), s.frames...)
}

func typedOpenPayload(t *testing.T, window uint32) []byte {
	t.Helper()
	payload, err := protocol.JSON(protocol.StreamOpen{Kind: protocol.StreamKindTerminal, Cols: 80, Rows: 24, Term: "xterm-256color", InitialWindow: window})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestTypedTerminalServerOpenDataResizeAndPeerClose(t *testing.T) {
	pty := newFakeTypedPTY()
	sink := &typedFrameSink{}
	server := newTypedTerminalServerWithStarter("/bin/sh", sink.write, func(string, uint16, uint16, string) (typedTerminalPTY, error) { return pty, nil })

	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: typedOpenPayload(t, 64<<10)}); err != nil {
		t.Fatal(err)
	}
	frames := sink.snapshot()
	if len(frames) != 1 || frames[0].Type != protocol.TypeStreamAccepted || frames[0].StreamID != 2 {
		t.Fatalf("accepted frames = %#v", frames)
	}
	var accepted protocol.StreamAccepted
	if err := protocol.ParseTypedStreamJSON(frames[0].Payload, &accepted); err != nil {
		t.Fatal(err)
	}
	if err := protocol.ValidateStreamAccepted(2, accepted); err != nil || accepted.InitialWindow != typedTerminalReceiveWindow {
		t.Fatalf("accepted = %#v err=%v", accepted, err)
	}

	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamData, StreamID: 2, Payload: []byte("hello")}); err != nil {
		t.Fatal(err)
	}
	resizePayload, _ := protocol.JSON(protocol.Resize{Cols: 120, Rows: 40})
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamResize, StreamID: 2, Payload: resizePayload}); err != nil {
		t.Fatal(err)
	}
	written, cols, rows := pty.snapshot()
	if written != "hello" || cols != 120 || rows != 40 {
		t.Fatalf("PTY state = written %q size %dx%d", written, cols, rows)
	}
	frames = sink.snapshot()
	if len(frames) != 2 || frames[1].Type != protocol.TypeStreamWindowUpdate {
		t.Fatalf("frames after input = %#v", frames)
	}

	closePayload, _ := protocol.JSON(protocol.StreamClose{Reason: "client_close"})
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: 2, Payload: closePayload}); err != nil {
		t.Fatal(err)
	}
	if server.states.isOpen(2) {
		t.Fatal("peer close left stream open")
	}
	if len(sink.snapshot()) != 2 {
		t.Fatal("peer close unexpectedly emitted an acknowledgement frame")
	}
}

func TestTypedTerminalServerRejectsMalformedStrictControls(t *testing.T) {
	server := newTypedTerminalServerWithStarter("/bin/sh", func(protocol.Frame) error { return nil }, func(string, uint16, uint16, string) (typedTerminalPTY, error) { return newFakeTypedPTY(), nil })
	badOpen := []byte(`{"kind":"terminal","cols":80,"rows":24,"initial_window":1,"unexpected":true}`)
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: badOpen}); !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("unknown open field error = %v", err)
	}
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: 2, Payload: []byte(`{} {}`)}); !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("trailing close JSON error = %v", err)
	}
}

func TestTypedTerminalServerRejectsDuplicateUnknownAndCreditOverflow(t *testing.T) {
	pty := newFakeTypedPTY()
	server := newTypedTerminalServerWithStarter("/bin/sh", func(protocol.Frame) error { return nil }, func(string, uint16, uint16, string) (typedTerminalPTY, error) { return pty, nil })
	openPayload := typedOpenPayload(t, protocol.MaxTypedStreamWindow)
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: openPayload}); err != nil {
		t.Fatal(err)
	}
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: openPayload}); !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("duplicate open error = %v", err)
	}
	updatePayload, _ := protocol.JSON(protocol.StreamWindowUpdate{Bytes: 1})
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: 2, Payload: updatePayload}); !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("credit overflow error = %v", err)
	}
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamData, StreamID: 99, Payload: []byte("x")}); !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("unknown stream data error = %v", err)
	}
	server.CloseAll()
}

func TestTypedTerminalServerLocalPTYFailureIsStreamScoped(t *testing.T) {
	sink := &typedFrameSink{}
	server := newTypedTerminalServerWithStarter("/bin/sh", sink.write, func(string, uint16, uint16, string) (typedTerminalPTY, error) {
		return nil, errors.New("start failed")
	})
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: typedOpenPayload(t, 64<<10)}); err != nil {
		t.Fatalf("local PTY start escaped as connection error: %v", err)
	}
	frames := sink.snapshot()
	if len(frames) != 1 || frames[0].Type != protocol.TypeStreamError || frames[0].StreamID != 2 {
		t.Fatalf("stream error frames = %#v", frames)
	}
	var streamErr protocol.StreamError
	if err := protocol.ParseTypedStreamJSON(frames[0].Payload, &streamErr); err != nil {
		t.Fatal(err)
	}
	if err := protocol.ValidateStreamError(2, streamErr); err != nil || streamErr.Code != "pty_start_failed" {
		t.Fatalf("stream error = %#v err=%v", streamErr, err)
	}
	if server.states.isOpen(2) {
		t.Fatal("failed PTY left stream open")
	}
}

func TestTypedTerminalServerPeerErrorClosesOnlyTargetStream(t *testing.T) {
	server := newTypedTerminalServerWithStarter("/bin/sh", func(protocol.Frame) error { return nil }, func(string, uint16, uint16, string) (typedTerminalPTY, error) { return newFakeTypedPTY(), nil })
	for _, id := range []uint32{2, 3} {
		if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: id, Payload: typedOpenPayload(t, 64<<10)}); err != nil {
			t.Fatal(err)
		}
	}
	payload, _ := protocol.JSON(protocol.StreamError{Code: "client_failed", Message: "child only"})
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamError, StreamID: 2, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if server.states.isOpen(2) || !server.states.isOpen(3) {
		t.Fatalf("peer error isolation failed: stream2=%v stream3=%v", server.states.isOpen(2), server.states.isOpen(3))
	}
	server.CloseAll()
}

func TestTypedTerminalServerOutputWaitsForCreditAndUsesBoundedChunks(t *testing.T) {
	pty := newFakeTypedPTY()
	sink := &typedFrameSink{}
	server := newTypedTerminalServerWithStarter("/bin/sh", sink.write, func(string, uint16, uint16, string) (typedTerminalPTY, error) { return pty, nil })
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: typedOpenPayload(t, 4)}); err != nil {
		t.Fatal(err)
	}
	child, err := server.openChild(2)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.sendData(2, child, []byte("abcdefgh")) }()

	time.Sleep(20 * time.Millisecond)
	frames := sink.snapshot()
	if len(frames) != 2 || frames[1].Type != protocol.TypeStreamData || string(frames[1].Payload) != "abcd" {
		t.Fatalf("frames before credit = %#v", frames)
	}
	updatePayload, _ := protocol.JSON(protocol.StreamWindowUpdate{Bytes: 4})
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: 2, Payload: updatePayload}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("sendData did not resume after credit")
	}
	frames = sink.snapshot()
	if len(frames) != 3 || string(frames[2].Payload) != "efgh" {
		t.Fatalf("frames after credit = %#v", frames)
	}
	server.CloseAll()
}

func TestTypedTerminalServerPTYCleanupFailureClosesStreamAndPersistsError(t *testing.T) {
	closeFailure := errors.New("injected typed PTY close failure")
	pty := newFakeTypedPTY()
	pty.closeErr = closeFailure
	var events []audit.Event
	tracker := newTypedTerminalAuditTracker("wd_peer", "direct_tcp", func(event audit.Event) {
		events = append(events, event)
	}, "session-123")
	server := newTypedTerminalServerWithStarter("/bin/sh", func(frame protocol.Frame) error {
		tracker.observeOutgoing(frame)
		return nil
	}, func(string, uint16, uint16, string) (typedTerminalPTY, error) {
		return pty, nil
	})
	server.setCloseObserver(tracker.closed)
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: typedOpenPayload(t, 64<<10)}); err != nil {
		t.Fatal(err)
	}
	closePayload, err := protocol.JSON(protocol.StreamClose{Reason: "client_revoked"})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: 2, Payload: closePayload}); !errors.Is(err, errTypedStreamCleanup) || !errors.Is(err, closeFailure) {
		t.Fatalf("peer close cleanup error = %v, want typed cleanup failure", err)
	}
	if server.states.isOpen(2) {
		t.Fatal("stream remained logically open after PTY close failure")
	}
	if len(events) != 2 || events[1].Type != "terminal.stream_closed" ||
		events[1].Outcome != "failed" || events[1].Reason != "peer_close" {
		t.Fatalf("stream audit events = %#v", events)
	}
	if err := server.CloseAllWithReason("client_revoked"); !errors.Is(err, closeFailure) {
		t.Fatalf("parent cleanup lost earlier PTY close error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("repeated parent cleanup emitted duplicate close events: %#v", events)
	}
}

func TestTypedTerminalServerParentCleanupWaitsForInFlightStreamClose(t *testing.T) {
	closeFailure := errors.New("injected in-flight PTY close failure")
	pty := newFakeTypedPTY()
	pty.closeErr = closeFailure
	pty.closeStarted = make(chan struct{})
	pty.closeRelease = make(chan struct{})
	server := newTypedTerminalServerWithStarter("/bin/sh", func(protocol.Frame) error { return nil }, func(string, uint16, uint16, string) (typedTerminalPTY, error) {
		return pty, nil
	})
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: typedOpenPayload(t, 64<<10)}); err != nil {
		t.Fatal(err)
	}
	peerClose, _ := protocol.JSON(protocol.StreamClose{Reason: "peer_close"})
	streamCloseDone := make(chan error, 1)
	go func() {
		streamCloseDone <- server.Handle(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: 2, Payload: peerClose})
	}()
	select {
	case <-pty.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("stream close did not enter PTY cleanup")
	}
	parentCleanupDone := make(chan error, 1)
	go func() { parentCleanupDone <- server.CloseAllWithReason("client_revoked") }()
	select {
	case err := <-parentCleanupDone:
		t.Fatalf("parent cleanup returned before in-flight PTY close completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(pty.closeRelease)
	if err := <-streamCloseDone; !errors.Is(err, errTypedStreamCleanup) || !errors.Is(err, closeFailure) {
		t.Fatalf("stream close error = %v, want retained PTY cleanup failure", err)
	}
	if err := <-parentCleanupDone; !errors.Is(err, closeFailure) {
		t.Fatalf("parent cleanup error = %v, want retained PTY cleanup failure", err)
	}
}

func waitTypedTerminalServerClosed(t *testing.T, server *typedTerminalServer) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.mu.Lock()
		closed := server.closed
		server.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("parent cleanup did not close the typed terminal server")
}

func TestTypedTerminalServerParentCleanupWaitsForInFlightStreamOpen(t *testing.T) {
	closeFailure := errors.New("injected late PTY close failure")
	pty := newFakeTypedPTY()
	pty.closeErr = closeFailure
	startEntered := make(chan struct{})
	releaseStart := make(chan struct{})
	sink := &typedFrameSink{}
	server := newTypedTerminalServerWithStarter("/bin/sh", sink.write, func(string, uint16, uint16, string) (typedTerminalPTY, error) {
		close(startEntered)
		<-releaseStart
		return pty, nil
	})
	var events []audit.Event
	tracker := newTypedTerminalAuditTracker("wd_peer", "direct_tcp", func(event audit.Event) {
		events = append(events, event)
	}, "session-123")
	server.setCloseObserver(tracker.closed)

	openDone := make(chan error, 1)
	go func() {
		openDone <- server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: typedOpenPayload(t, 64<<10)})
	}()
	select {
	case <-startEntered:
	case <-time.After(time.Second):
		t.Fatal("stream open did not enter PTY startup")
	}

	cleanupDone := make(chan error, 1)
	go func() { cleanupDone <- server.CloseAllWithReason("client_revoked") }()
	waitTypedTerminalServerClosed(t, server)
	select {
	case err := <-cleanupDone:
		t.Fatalf("parent cleanup returned before the in-flight PTY starter completed: %v", err)
	default:
	}

	close(releaseStart)
	openErr := <-openDone
	if !errors.Is(openErr, errTypedStreamCleanup) || !errors.Is(openErr, closeFailure) {
		t.Fatalf("late stream-open error = %v, want retained PTY cleanup failure", openErr)
	}
	cleanupErr := <-cleanupDone
	if !errors.Is(cleanupErr, closeFailure) {
		t.Fatalf("parent cleanup omitted late PTY close failure: %v", cleanupErr)
	}
	select {
	case <-pty.closed:
	case <-time.After(time.Second):
		t.Fatal("late PTY was not closed before parent cleanup completed")
	}
	if server.states.isOpen(2) {
		t.Fatal("late stream reservation remained open after parent cleanup")
	}
	if frames := sink.snapshot(); len(frames) != 0 {
		t.Fatalf("late stream was accepted after parent cleanup began: %#v", frames)
	}
	if len(events) != 0 {
		t.Fatalf("unaccepted stream unexpectedly emitted lifecycle audit events: %#v", events)
	}
}

func TestTypedTerminalServerRejectsBufferedOpenAfterParentCleanup(t *testing.T) {
	starts := 0
	server := newTypedTerminalServerWithStarter("/bin/sh", func(protocol.Frame) error { return nil }, func(string, uint16, uint16, string) (typedTerminalPTY, error) {
		starts++
		return newFakeTypedPTY(), nil
	})
	if err := server.CloseAllWithReason("client_revoked"); err != nil {
		t.Fatal(err)
	}

	// This frame models a StreamOpen already buffered by the session reader
	// before revocation, but not dispatched until after parent cleanup.
	err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: typedOpenPayload(t, 64<<10)})
	if !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("post-cleanup buffered StreamOpen error = %v", err)
	}
	if starts != 0 {
		t.Fatalf("post-cleanup buffered StreamOpen started %d PTYs", starts)
	}
}

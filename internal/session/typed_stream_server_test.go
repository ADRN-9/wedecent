package session

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/protocol"
)

type fakeTypedPTY struct {
	mu        sync.Mutex
	written   bytes.Buffer
	cols      uint16
	rows      uint16
	resizeErr error
	writeErr  error
	closed    chan struct{}
	closeOne  sync.Once
}

func newFakeTypedPTY() *fakeTypedPTY             { return &fakeTypedPTY{closed: make(chan struct{})} }
func (p *fakeTypedPTY) Read([]byte) (int, error) { <-p.closed; return 0, io.EOF }
func (p *fakeTypedPTY) Wait() error              { <-p.closed; return nil }
func (p *fakeTypedPTY) Close() error             { p.closeOne.Do(func() { close(p.closed) }); return nil }
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

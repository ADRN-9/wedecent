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
	mu       sync.Mutex
	written  bytes.Buffer
	cols     uint16
	rows     uint16
	closed   chan struct{}
	closeOne sync.Once
}

func newFakeTypedPTY() *fakeTypedPTY {
	return &fakeTypedPTY{closed: make(chan struct{})}
}

func (p *fakeTypedPTY) Read([]byte) (int, error) {
	<-p.closed
	return 0, io.EOF
}

func (p *fakeTypedPTY) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.written.Write(data)
}

func (p *fakeTypedPTY) Resize(cols, rows uint16) error {
	p.mu.Lock()
	p.cols = cols
	p.rows = rows
	p.mu.Unlock()
	return nil
}

func (p *fakeTypedPTY) Wait() error {
	<-p.closed
	return nil
}

func (p *fakeTypedPTY) Close() error {
	p.closeOne.Do(func() { close(p.closed) })
	return nil
}

func (p *fakeTypedPTY) snapshot() (string, uint16, uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.written.String(), p.cols, p.rows
}

func TestTypedTerminalServerOpenDataResizeAndClose(t *testing.T) {
	pty := newFakeTypedPTY()
	var mu sync.Mutex
	var frames []protocol.Frame
	server := newTypedTerminalServerWithStarter("/bin/sh", func(frame protocol.Frame) error {
		mu.Lock()
		frames = append(frames, frame)
		mu.Unlock()
		return nil
	}, func(string, uint16, uint16, string) (typedTerminalPTY, error) {
		return pty, nil
	})

	openPayload, err := protocol.JSON(protocol.StreamOpen{
		Kind:          protocol.StreamKindTerminal,
		Cols:          80,
		Rows:          24,
		Term:          "xterm-256color",
		InitialWindow: 64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: openPayload}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	if len(frames) != 1 || frames[0].Type != protocol.TypeStreamAccepted || frames[0].StreamID != 2 {
		t.Fatalf("accepted frames = %#v", frames)
	}
	var accepted protocol.StreamAccepted
	if err := protocol.ParseJSON(frames[0].Payload, &accepted); err != nil {
		mu.Unlock()
		t.Fatal(err)
	}
	mu.Unlock()
	if accepted.InitialWindow != typedTerminalReceiveWindow {
		t.Fatalf("accepted initial window = %d", accepted.InitialWindow)
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

	mu.Lock()
	if len(frames) != 2 || frames[1].Type != protocol.TypeStreamWindowUpdate {
		t.Fatalf("frames after input = %#v", frames)
	}
	var update protocol.StreamWindowUpdate
	if err := protocol.ParseJSON(frames[1].Payload, &update); err != nil {
		mu.Unlock()
		t.Fatal(err)
	}
	mu.Unlock()
	if update.Bytes != 5 {
		t.Fatalf("window update = %d", update.Bytes)
	}

	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: 2}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(frames) != 3 || frames[2].Type != protocol.TypeStreamClose || frames[2].StreamID != 2 {
		t.Fatalf("close frames = %#v", frames)
	}
}

func TestTypedTerminalServerRejectsDuplicateUnknownAndCreditOverflow(t *testing.T) {
	pty := newFakeTypedPTY()
	server := newTypedTerminalServerWithStarter("/bin/sh", func(protocol.Frame) error { return nil }, func(string, uint16, uint16, string) (typedTerminalPTY, error) {
		return pty, nil
	})
	openPayload, _ := protocol.JSON(protocol.StreamOpen{
		Kind:          protocol.StreamKindTerminal,
		Cols:          80,
		Rows:          24,
		InitialWindow: protocol.MaxTypedStreamWindow,
	})
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

func TestTypedTerminalServerOutputWaitsForCreditAndUsesBoundedChunks(t *testing.T) {
	pty := newFakeTypedPTY()
	var mu sync.Mutex
	var frames []protocol.Frame
	server := newTypedTerminalServerWithStarter("/bin/sh", func(frame protocol.Frame) error {
		mu.Lock()
		frames = append(frames, frame)
		mu.Unlock()
		return nil
	}, func(string, uint16, uint16, string) (typedTerminalPTY, error) {
		return pty, nil
	})

	openPayload, _ := protocol.JSON(protocol.StreamOpen{
		Kind:          protocol.StreamKindTerminal,
		Cols:          80,
		Rows:          24,
		InitialWindow: 4,
	})
	if err := server.Handle(protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: openPayload}); err != nil {
		t.Fatal(err)
	}
	child, err := server.openChild(2)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.sendData(2, child, []byte("abcdefgh")) }()

	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	if len(frames) != 2 || string(frames[1].Payload) != "abcd" {
		got := append([]protocol.Frame(nil), frames...)
		mu.Unlock()
		t.Fatalf("frames before credit = %#v", got)
	}
	mu.Unlock()

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

	mu.Lock()
	defer mu.Unlock()
	if len(frames) != 3 || string(frames[2].Payload) != "efgh" {
		t.Fatalf("frames after credit = %#v", frames)
	}
	server.CloseAll()
}

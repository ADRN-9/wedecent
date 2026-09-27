package coreapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeMultiplexTerminalHandle struct {
	*fakeTerminalConnectionHandle

	streamsMu sync.Mutex
	nextID    uint32
	children  map[uint32]*fakeTerminalConnectionHandle
	openErr   error
}

func newFakeMultiplexTerminalHandle() *fakeMultiplexTerminalHandle {
	return &fakeMultiplexTerminalHandle{
		fakeTerminalConnectionHandle: newFakeTerminalConnectionHandle(),
		nextID:                       2,
		children:                     make(map[uint32]*fakeTerminalConnectionHandle),
	}
}

func (h *fakeMultiplexTerminalHandle) OpenTerminalStream(ctx context.Context, cols, rows uint16, term string) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	h.streamsMu.Lock()
	defer h.streamsMu.Unlock()
	if h.openErr != nil {
		return 0, h.openErr
	}
	id := h.nextID
	h.nextID++
	h.children[id] = newFakeTerminalConnectionHandle()
	return id, nil
}

func (h *fakeMultiplexTerminalHandle) ReadTerminalStream(ctx context.Context, id uint32, maxBytes int) ([]byte, bool, error) {
	child, err := h.child(id)
	if err != nil {
		return nil, true, err
	}
	return child.ReadTerminal(ctx, maxBytes)
}

func (h *fakeMultiplexTerminalHandle) WriteTerminalStream(ctx context.Context, id uint32, data []byte) error {
	child, err := h.child(id)
	if err != nil {
		return err
	}
	return child.WriteTerminal(ctx, data)
}

func (h *fakeMultiplexTerminalHandle) ResizeTerminalStream(ctx context.Context, id uint32, cols, rows uint16) error {
	child, err := h.child(id)
	if err != nil {
		return err
	}
	return child.ResizeTerminal(ctx, cols, rows)
}

func (h *fakeMultiplexTerminalHandle) CloseTerminalStream(ctx context.Context, id uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	child, err := h.child(id)
	if err != nil {
		return err
	}
	closeTestDone(child.done)
	return nil
}

func (h *fakeMultiplexTerminalHandle) Close() error {
	if err := h.fakeConnectionHandle.Close(); err != nil {
		return err
	}
	closeTestDone(h.done)
	h.streamsMu.Lock()
	children := make([]*fakeTerminalConnectionHandle, 0, len(h.children))
	for _, child := range h.children {
		children = append(children, child)
	}
	h.streamsMu.Unlock()
	for _, child := range children {
		closeTestDone(child.done)
	}
	return nil
}

func (h *fakeMultiplexTerminalHandle) child(id uint32) (*fakeTerminalConnectionHandle, error) {
	h.streamsMu.Lock()
	defer h.streamsMu.Unlock()
	child := h.children[id]
	if child == nil {
		return nil, io.ErrClosedPipe
	}
	return child, nil
}

func terminalStreamRandomReader() *bytes.Reader {
	data := make([]byte, 0, 18*4)
	for _, value := range []byte{0x61, 0x62, 0x63, 0x64} {
		data = append(data, bytes.Repeat([]byte{value}, 18)...)
	}
	return bytes.NewReader(data)
}

func newTerminalStreamTestService(t *testing.T, handle ConnectionHandle) *ConnectionService {
	t.Helper()
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: &fakeConnectionBackend{opened: OpenedConnection{
			Path:   v1.ConnectionPathRelay,
			Handle: handle,
		}},
		Network: newConnectionTestNetwork(t),
		Random:  terminalStreamRandomReader(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestTerminalStreamServiceOpensOpaqueChildrenAndKeepsSiblingsAlive(t *testing.T) {
	parent := newFakeMultiplexTerminalHandle()
	service := newTerminalStreamTestService(t, parent)
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}

	streamA, err := service.OpenTerminalStream(context.Background(), v1.TerminalStreamOpenRequest{
		ConnectionID: connection.ID, Cols: 80, Rows: 24, Term: "xterm-256color",
	})
	if err != nil {
		t.Fatal(err)
	}
	streamB, err := service.OpenTerminalStream(context.Background(), v1.TerminalStreamOpenRequest{
		ConnectionID: connection.ID, Cols: 100, Rows: 30, Term: "xterm-256color",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(streamA.ID, terminalStreamIDPrefix) || !strings.HasPrefix(streamB.ID, terminalStreamIDPrefix) || streamA.ID == streamB.ID {
		t.Fatalf("opaque terminal IDs = %q, %q", streamA.ID, streamB.ID)
	}
	if streamA.ConnectionID != connection.ID || streamB.ConnectionID != connection.ID {
		t.Fatalf("stream connection IDs = %q, %q", streamA.ConnectionID, streamB.ConnectionID)
	}

	childA, err := parent.child(2)
	if err != nil {
		t.Fatal(err)
	}
	childB, err := parent.child(3)
	if err != nil {
		t.Fatal(err)
	}
	childA.mu.Lock()
	childA.output = [][]byte{[]byte("child-a")}
	childA.mu.Unlock()

	read, err := service.ReadTerminalStream(context.Background(), v1.TerminalStreamReadRequest{
		ConnectionID: connection.ID, TerminalID: streamA.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(read.Data) != "child-a" || read.Closed {
		t.Fatalf("stream A read = %#v", read)
	}
	if err := service.WriteTerminalStream(context.Background(), v1.TerminalStreamWriteRequest{
		ConnectionID: connection.ID, TerminalID: streamB.ID, Data: []byte("echo b\n"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.ResizeTerminalStream(context.Background(), v1.TerminalStreamResizeRequest{
		ConnectionID: connection.ID, TerminalID: streamB.ID, Cols: 132, Rows: 43,
	}); err != nil {
		t.Fatal(err)
	}
	childB.mu.Lock()
	if len(childB.writes) != 1 || string(childB.writes[0]) != "echo b\n" || childB.cols != 132 || childB.rows != 43 {
		t.Fatalf("stream B state writes=%q size=%dx%d", childB.writes, childB.cols, childB.rows)
	}
	childB.mu.Unlock()

	if err := service.CloseTerminalStream(context.Background(), v1.TerminalStreamCloseRequest{
		ConnectionID: connection.ID, TerminalID: streamA.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if testChannelClosed(parent.done) {
		t.Fatal("closing child A closed the parent")
	}
	if err := service.WriteTerminalStream(context.Background(), v1.TerminalStreamWriteRequest{
		ConnectionID: connection.ID, TerminalID: streamB.ID, Data: []byte("still alive\n"),
	}); err != nil {
		t.Fatalf("sibling write after child close: %v", err)
	}
	if _, err := service.ReadTerminalStream(context.Background(), v1.TerminalStreamReadRequest{
		ConnectionID: connection.ID, TerminalID: streamA.ID,
	}); !errors.Is(err, ErrTerminalUnavailable) {
		t.Fatalf("closed child read error = %v, want terminal unavailable", err)
	}
}

func TestTerminalStreamServiceParentDisconnectCleansChildren(t *testing.T) {
	parent := newFakeMultiplexTerminalHandle()
	service := newTerminalStreamTestService(t, parent)
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := service.OpenTerminalStream(context.Background(), v1.TerminalStreamOpenRequest{
		ConnectionID: connection.ID, Cols: 80, Rows: 24,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := service.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: connection.ID}); err != nil {
		t.Fatal(err)
	}
	if !testChannelClosed(parent.done) {
		t.Fatal("parent disconnect did not close multiplex parent")
	}
	if err := service.WriteTerminalStream(context.Background(), v1.TerminalStreamWriteRequest{
		ConnectionID: connection.ID, TerminalID: stream.ID, Data: []byte("x"),
	}); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("write after parent disconnect error = %v, want connection not found", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		service.mu.Lock()
		_, exists := service.streams[stream.ID]
		service.mu.Unlock()
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("logical child was not removed after parent close")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTerminalStreamServiceFailsClosedWithoutNegotiatedMultiplexHandle(t *testing.T) {
	service := newTerminalStreamTestService(t, newFakeTerminalConnectionHandle())
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.OpenTerminalStream(context.Background(), v1.TerminalStreamOpenRequest{
		ConnectionID: connection.ID, Cols: 80, Rows: 24,
	}); !errors.Is(err, ErrTerminalUnavailable) {
		t.Fatalf("open on non-multiplex handle error = %v, want terminal unavailable", err)
	}
}

func TestTerminalStreamServiceRejectsInvalidRequestsAndSanitizesOpenFailure(t *testing.T) {
	parent := newFakeMultiplexTerminalHandle()
	service := newTerminalStreamTestService(t, parent)
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.OpenTerminalStream(context.Background(), v1.TerminalStreamOpenRequest{
		ConnectionID: connection.ID, Cols: 80, Rows: 24, Term: "bad\nterm",
	}); !errors.Is(err, ErrInvalidTerminalRequest) {
		t.Fatalf("invalid TERM error = %v", err)
	}

	parent.streamsMu.Lock()
	parent.openErr = errors.New("sensitive backend detail")
	parent.streamsMu.Unlock()
	if _, err := service.OpenTerminalStream(context.Background(), v1.TerminalStreamOpenRequest{
		ConnectionID: connection.ID, Cols: 80, Rows: 24,
	}); !errors.Is(err, ErrTerminalUnavailable) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("sanitized open error = %v", err)
	}

	if err := service.WriteTerminalStream(context.Background(), v1.TerminalStreamWriteRequest{
		ConnectionID: connection.ID, TerminalID: "term_not-valid", Data: []byte("x"),
	}); !errors.Is(err, ErrInvalidTerminalRequest) {
		t.Fatalf("invalid terminal ID error = %v", err)
	}
}

func closeTestDone(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

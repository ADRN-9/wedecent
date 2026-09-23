package coreapi

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeTerminalConnectionHandle struct {
	fakeConnectionHandle

	mu        sync.Mutex
	done      chan struct{}
	output    [][]byte
	writes    [][]byte
	cols      uint16
	rows      uint16
	readErr   error
	writeErr  error
	resizeErr error
}

func newFakeTerminalConnectionHandle() *fakeTerminalConnectionHandle {
	return &fakeTerminalConnectionHandle{done: make(chan struct{})}
}

func (h *fakeTerminalConnectionHandle) Done() <-chan struct{} {
	return h.done
}

func (h *fakeTerminalConnectionHandle) ReadTerminal(ctx context.Context, maxBytes int) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	h.mu.Lock()
	if h.readErr != nil {
		err := h.readErr
		h.mu.Unlock()
		return nil, false, err
	}
	if len(h.output) != 0 {
		chunk := h.output[0]
		n := len(chunk)
		if n > maxBytes {
			n = maxBytes
		}
		out := append([]byte(nil), chunk[:n]...)
		if n == len(chunk) {
			h.output = h.output[1:]
		} else {
			h.output[0] = chunk[n:]
		}
		closed := len(h.output) == 0 && testChannelClosed(h.done)
		h.mu.Unlock()
		return out, closed, nil
	}
	closed := testChannelClosed(h.done)
	h.mu.Unlock()
	if closed {
		return nil, true, nil
	}
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case <-h.done:
		return nil, true, nil
	}
}

func (h *fakeTerminalConnectionHandle) WriteTerminal(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.writeErr != nil {
		return h.writeErr
	}
	h.writes = append(h.writes, append([]byte(nil), data...))
	return nil
}

func (h *fakeTerminalConnectionHandle) ResizeTerminal(ctx context.Context, cols, rows uint16) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.resizeErr != nil {
		return h.resizeErr
	}
	h.cols, h.rows = cols, rows
	return nil
}

func TestTerminalServiceReadWriteResizeAndRetainFinalOutput(t *testing.T) {
	handle := newFakeTerminalConnectionHandle()
	handle.output = [][]byte{[]byte("final output")}
	backend := &fakeConnectionBackend{opened: OpenedConnection{
		Path:   v1.ConnectionPathRelay,
		Handle: handle,
	}}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x51}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}

	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WriteTerminal(context.Background(), v1.TerminalWriteRequest{
		ConnectionID: connection.ID,
		Data:         []byte("echo hello\n"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.ResizeTerminal(context.Background(), v1.TerminalResizeRequest{
		ConnectionID: connection.ID,
		Cols:         120,
		Rows:         40,
	}); err != nil {
		t.Fatal(err)
	}

	handle.mu.Lock()
	if len(handle.writes) != 1 || string(handle.writes[0]) != "echo hello\n" {
		t.Fatalf("writes = %#v", handle.writes)
	}
	if handle.cols != 120 || handle.rows != 40 {
		t.Fatalf("resize = %dx%d", handle.cols, handle.rows)
	}
	handle.mu.Unlock()

	close(handle.done)
	deadline := time.Now().Add(time.Second)
	for {
		service.mu.Lock()
		_, active := service.active[connection.ID]
		stream, retained := service.streams[connection.ID]
		service.mu.Unlock()
		if !active && retained && stream.closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("remote close was not observed")
		}
		time.Sleep(time.Millisecond)
	}

	result, err := service.ReadTerminal(context.Background(), v1.TerminalReadRequest{
		ConnectionID: connection.ID,
		MaxBytes:     v1.MaxTerminalChunkBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Data) != "final output" || !result.Closed {
		t.Fatalf("terminal read = %#v", result)
	}
	if _, err := service.ReadTerminal(context.Background(), v1.TerminalReadRequest{
		ConnectionID: connection.ID,
	}); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("second read error = %v, want connection not found", err)
	}
}

func TestTerminalServiceRejectsUnavailableAndOversizedOperations(t *testing.T) {
	backend := &fakeConnectionBackend{opened: OpenedConnection{
		Path:   v1.ConnectionPathRelay,
		Handle: &fakeConnectionHandle{},
	}}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x52}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WriteTerminal(context.Background(), v1.TerminalWriteRequest{
		ConnectionID: connection.ID,
		Data:         []byte("x"),
	}); !errors.Is(err, ErrTerminalUnavailable) {
		t.Fatalf("write error = %v, want terminal unavailable", err)
	}
	if _, err := service.ReadTerminal(context.Background(), v1.TerminalReadRequest{
		ConnectionID: connection.ID,
		MaxBytes:     v1.MaxTerminalChunkBytes + 1,
	}); !errors.Is(err, ErrInvalidTerminalRequest) {
		t.Fatalf("oversized read error = %v, want invalid terminal request", err)
	}
}

func testChannelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

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

type observableFakeConnectionHandle struct {
	fakeConnectionHandle
	done chan struct{}
}

func (h *observableFakeConnectionHandle) Done() <-chan struct{} { return h.done }

type observableRetryConnectionHandle struct {
	fakeConnectionHandle
	done     chan struct{}
	doneOnce sync.Once
}

func (h *observableRetryConnectionHandle) Done() <-chan struct{} { return h.done }

func (h *observableRetryConnectionHandle) Close() error {
	h.doneOnce.Do(func() { close(h.done) })
	return h.fakeConnectionHandle.Close()
}

func TestConnectionServicePreservesRequestCancellationFromBackendOpen(t *testing.T) {
	backend := &blockingConnectionBackend{
		started: make(chan struct{}),
		release: make(chan struct{}),
		handle:  &fakeConnectionHandle{},
	}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x31}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := service.Connect(ctx, v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
		result <- err
	}()
	<-backend.started
	cancel()

	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect error = %v, want context.Canceled", err)
	}
}

func TestConnectionServiceShutdownCancelsBackendOpen(t *testing.T) {
	backend := &blockingConnectionBackend{
		started: make(chan struct{}),
		release: make(chan struct{}),
		handle:  &fakeConnectionHandle{},
	}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x32}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
		result <- err
	}()
	<-backend.started
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrConnectionServiceClosed) {
			t.Fatalf("Connect error = %v, want ErrConnectionServiceClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backend open was not canceled by service shutdown")
	}
}

func TestConnectionServiceRemoteCloseRemovesPublishedPath(t *testing.T) {
	handle := &observableFakeConnectionHandle{done: make(chan struct{})}
	network := newConnectionTestNetwork(t)
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: &fakeConnectionBackend{opened: OpenedConnection{Path: v1.ConnectionPathRelay, Handle: handle}},
		Network: network,
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x33}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	close(handle.done)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, routeErr := network.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: connection.ID})
		if errors.Is(routeErr, ErrRouteNotFound) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := network.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: connection.ID}); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("route after remote close = %v, want ErrRouteNotFound", err)
	}
	if err := service.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: connection.ID}); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("Disconnect after remote close = %v, want ErrConnectionNotFound", err)
	}
}

func TestConnectionServiceRemoteCloseDuringFailedDisconnectRemainsRetryable(t *testing.T) {
	handle := &observableRetryConnectionHandle{
		fakeConnectionHandle: fakeConnectionHandle{closeErr: errors.New("temporary close failure")},
		done:                 make(chan struct{}),
	}
	network := newConnectionTestNetwork(t)
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: &fakeConnectionBackend{opened: OpenedConnection{Path: v1.ConnectionPathRelay, Handle: handle}},
		Network: network,
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x34}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}

	if err := service.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: connection.ID}); !errors.Is(err, ErrConnectionOperation) {
		t.Fatalf("first Disconnect error = %v, want ErrConnectionOperation", err)
	}
	// Close signaled Done while the local disconnect was in progress. Give the
	// observer time to process that signal; it must not steal retry ownership.
	time.Sleep(20 * time.Millisecond)
	handle.closeErr = nil
	if err := service.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: connection.ID}); err != nil {
		t.Fatalf("retry Disconnect = %v", err)
	}
	if handle.closeCount() != 2 {
		t.Fatalf("close count = %d, want 2", handle.closeCount())
	}
}

func TestConnectionServiceRetriesConnectionIDCollision(t *testing.T) {
	randomBytes := append([]byte{}, bytes.Repeat([]byte{0x41}, 18)...)
	randomBytes = append(randomBytes, bytes.Repeat([]byte{0x41}, 18)...)
	randomBytes = append(randomBytes, bytes.Repeat([]byte{0x42}, 18)...)

	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: &fakeConnectionBackend{opened: OpenedConnection{
			Path:   v1.ConnectionPathRelay,
			Handle: &fakeConnectionHandle{},
		}},
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(randomBytes),
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_other000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatalf("duplicate connection ID %q", first.ID)
	}
}

func TestConnectionServiceFailedDisconnectRemainsRetryable(t *testing.T) {
	handle := &fakeConnectionHandle{closeErr: errors.New("temporary close failure")}
	network := newConnectionTestNetwork(t)
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: &fakeConnectionBackend{opened: OpenedConnection{
			Path:   v1.ConnectionPathRelay,
			Handle: handle,
		}},
		Network: network,
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x51}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}

	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: connection.ID}); !errors.Is(err, ErrConnectionOperation) {
		t.Fatalf("first Disconnect error = %v, want ErrConnectionOperation", err)
	}
	if _, err := network.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: connection.ID}); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("route after failed disconnect = %v, want ErrRouteNotFound", err)
	}

	handle.closeErr = nil
	if err := service.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: connection.ID}); err != nil {
		t.Fatalf("retry Disconnect = %v", err)
	}
	if handle.closeCount() != 2 {
		t.Fatalf("close count = %d, want 2", handle.closeCount())
	}
}

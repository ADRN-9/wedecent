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
	"wedecent.com/wedecent/internal/mesh"
)

type fakeConnectionHandle struct {
	mu       sync.Mutex
	closed   int
	closeErr error
}

func (h *fakeConnectionHandle) Close() error {
	h.mu.Lock()
	h.closed++
	h.mu.Unlock()
	return h.closeErr
}

func (h *fakeConnectionHandle) closeCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

type fakeConnectionBackend struct {
	mu     sync.Mutex
	opened OpenedConnection
	err    error
	calls  int
}

func (b *fakeConnectionBackend) Open(context.Context, string) (OpenedConnection, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	return b.opened, b.err
}

type blockingConnectionBackend struct {
	started chan struct{}
	release chan struct{}
	handle  *fakeConnectionHandle
	once    sync.Once
}

func (b *blockingConnectionBackend) Open(ctx context.Context, _ string) (OpenedConnection, error) {
	b.once.Do(func() { close(b.started) })
	select {
	case <-ctx.Done():
		return OpenedConnection{}, ctx.Err()
	case <-b.release:
		return OpenedConnection{Path: v1.ConnectionPathRelay, Handle: b.handle}, nil
	}
}

func newConnectionTestNetwork(t *testing.T) *NetworkReadService {
	t.Helper()
	network, err := NewNetworkReadService("wd_source00000000", DefaultTransportStatuses())
	if err != nil {
		t.Fatal(err)
	}
	return network
}

func TestConnectionServiceConnectDisconnectPublishesPath(t *testing.T) {
	handle := &fakeConnectionHandle{}
	backend := &fakeConnectionBackend{opened: OpenedConnection{
		Path:   v1.ConnectionPathRelay,
		Handle: handle,
	}}
	network := newConnectionTestNetwork(t)
	now := time.Date(2026, 9, 22, 18, 0, 0, 0, time.UTC)
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: network,
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x42}, 18)),
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(connection.ID, "conn_") || connection.DeviceID != "wd_dest0000000000" {
		t.Fatalf("connection = %#v", connection)
	}
	if connection.State != v1.ConnectionStateConnected || connection.Path != v1.ConnectionPathRelay || !connection.StartedAt.Equal(now) {
		t.Fatalf("connection = %#v", connection)
	}

	status, err := network.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: connection.ID})
	if err != nil {
		t.Fatal(err)
	}
	if status.DestinationID != connection.DeviceID || status.Path != v1.ConnectionPathRelay {
		t.Fatalf("path status = %#v", status)
	}

	if err := service.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: connection.ID}); err != nil {
		t.Fatal(err)
	}
	if handle.closeCount() != 1 {
		t.Fatalf("close count = %d, want 1", handle.closeCount())
	}
	if _, err := network.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: connection.ID}); !errors.Is(err, ErrRouteNotFound) {
		t.Fatalf("route after disconnect error = %v", err)
	}
	if err := service.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: connection.ID}); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("second disconnect error = %v", err)
	}
}

func TestConnectionServicePublishesValidatedRoutedPath(t *testing.T) {
	now := time.Date(2026, 9, 22, 18, 0, 0, 0, time.UTC)
	route := mesh.Route{
		ID:          "route-1",
		Source:      "wd_source00000000",
		Destination: "wd_dest0000000000",
		Hops: []mesh.RouteHop{
			{From: "wd_source00000000", To: "wd_router00000000", Transport: mesh.TransportLAN, Cost: 10},
			{From: "wd_router00000000", To: "wd_dest0000000000", Transport: mesh.TransportInternet, Cost: 20},
		},
		ExpiresAt: now.Add(time.Minute),
	}
	handle := &fakeConnectionHandle{}
	backend := &fakeConnectionBackend{opened: OpenedConnection{
		Path:   v1.ConnectionPathRouted,
		Route:  &route,
		Handle: handle,
	}}
	network := newConnectionTestNetwork(t)
	network.now = func() time.Time { return now }
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: network,
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x24}, 18)),
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	status, err := network.GetRouteStatus(context.Background(), v1.GetRouteStatusRequest{ConnectionID: connection.ID})
	if err != nil {
		t.Fatal(err)
	}
	if status.RouterID != "wd_router00000000" || len(status.Hops) != 2 {
		t.Fatalf("route status = %#v", status)
	}
}

func TestConnectionServiceFailsClosedOnInvalidBackendResult(t *testing.T) {
	for name, opened := range map[string]OpenedConnection{
		"nil handle": {Path: v1.ConnectionPathRelay},
		"bad path":   {Path: "unknown", Handle: &fakeConnectionHandle{}},
		"routed without route": {
			Path:   v1.ConnectionPathRouted,
			Handle: &fakeConnectionHandle{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			network := newConnectionTestNetwork(t)
			service, err := NewConnectionService(ConnectionServiceConfig{
				Backend: &fakeConnectionBackend{opened: opened},
				Network: network,
				Random:  bytes.NewReader(bytes.Repeat([]byte{1}, 18)),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
			if !errors.Is(err, ErrConnectionOperation) {
				t.Fatalf("Connect error = %v", err)
			}
			if opened.Handle != nil {
				handle := opened.Handle.(*fakeConnectionHandle)
				if handle.closeCount() != 1 {
					t.Fatalf("close count = %d, want 1", handle.closeCount())
				}
			}
		})
	}
}

func TestConnectionServiceReservesCapacityWhileOpening(t *testing.T) {
	backend := &blockingConnectionBackend{
		started: make(chan struct{}),
		release: make(chan struct{}),
		handle:  &fakeConnectionHandle{},
	}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend:   backend,
		Network:   newConnectionTestNetwork(t),
		MaxActive: 1,
		Random:    bytes.NewReader(bytes.Repeat([]byte{7}, 18)),
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

	_, err = service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_other000000000"})
	if !errors.Is(err, ErrConnectionLimit) {
		t.Fatalf("second Connect error = %v, want ErrConnectionLimit", err)
	}
	close(backend.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestConnectionServiceBackendAndRandomFailuresDoNotLeakHandles(t *testing.T) {
	backendFailure := &fakeConnectionBackend{err: errors.New("backend secret detail")}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backendFailure,
		Network: newConnectionTestNetwork(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"}); !errors.Is(err, ErrConnectionOperation) {
		t.Fatalf("backend failure = %v", err)
	}

	handle := &fakeConnectionHandle{}
	service, err = NewConnectionService(ConnectionServiceConfig{
		Backend: &fakeConnectionBackend{opened: OpenedConnection{Path: v1.ConnectionPathRelay, Handle: handle}},
		Network: newConnectionTestNetwork(t),
		Random:  errReader{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"}); !errors.Is(err, ErrConnectionOperation) {
		t.Fatalf("random failure = %v", err)
	}
	if handle.closeCount() != 1 {
		t.Fatalf("close count = %d, want 1", handle.closeCount())
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestConnectionServiceCloseTearsDownAndRejectsFutureConnect(t *testing.T) {
	handle := &fakeConnectionHandle{}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: &fakeConnectionBackend{opened: OpenedConnection{Path: v1.ConnectionPathRelay, Handle: handle}},
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{9}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"}); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if handle.closeCount() != 1 {
		t.Fatalf("close count = %d, want 1", handle.closeCount())
	}
	if _, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_other000000000"}); !errors.Is(err, ErrConnectionServiceClosed) {
		t.Fatalf("Connect after Close error = %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

func TestConnectionServiceValidatesRequestsAndCancellation(t *testing.T) {
	backend := &fakeConnectionBackend{opened: OpenedConnection{Path: v1.ConnectionPathRelay, Handle: &fakeConnectionHandle{}}}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Connect(context.Background(), v1.ConnectRequest{}); !errors.Is(err, ErrInvalidConnectionRequest) {
		t.Fatalf("empty device error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Connect(ctx, v1.ConnectRequest{DeviceID: "wd_dest0000000000"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Connect error = %v", err)
	}
	if err := service.Disconnect(context.Background(), v1.DisconnectRequest{}); !errors.Is(err, ErrInvalidConnectionRequest) {
		t.Fatalf("empty disconnect error = %v", err)
	}
}

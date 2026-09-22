package coreapi

import (
	"bytes"
	"context"
	"errors"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

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

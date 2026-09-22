package coreprocess

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/trust"
)

type processConnectionHandle struct {
	mu     sync.Mutex
	closed int
	done   chan struct{}
}

func (h *processConnectionHandle) Close() error {
	h.mu.Lock()
	h.closed++
	select {
	case <-h.done:
	default:
		close(h.done)
	}
	h.mu.Unlock()
	return nil
}
func (h *processConnectionHandle) Done() <-chan struct{} { return h.done }
func (h *processConnectionHandle) closeCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

type processConnectionBackend struct{ handle *processConnectionHandle }

func (b processConnectionBackend) Open(context.Context, string) (coreapi.OpenedConnection, error) {
	return coreapi.OpenedConnection{Path: v1.ConnectionPathDirect, Handle: b.handle}, nil
}

func TestOpenRuntimeComposesConnectionCapabilityAndOwnsShutdown(t *testing.T) {
	dir := t.TempDir()
	if _, err := identity.Ensure(dir, "core-connect-test"); err != nil {
		t.Fatal(err)
	}
	devices, err := trust.Open(filepath.Join(dir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	destinationID := "wd_bbbbbbbbbbbbbbbb"
	if err := devices.Put(trust.Peer{ID: destinationID, Name: "destination", Fingerprint: "test-fingerprint", Endpoint: "tcp://127.0.0.1:7443"}); err != nil {
		t.Fatal(err)
	}

	handle := &processConnectionHandle{done: make(chan struct{})}
	runtime, err := OpenRuntime(Config{
		ClientStateDir:    dir,
		ConnectionBackend: processConnectionBackend{handle: handle},
	})
	if err != nil {
		t.Fatal(err)
	}

	client, serverConn := net.Pipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- runtime.Server.ServeOne(context.Background(), serverConn) }()
	params, err := json.Marshal(v1.ConnectRequest{DeviceID: destinationID})
	if err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteRequest(client, ipc.Request{Version: v1.Version, ID: "connect-1", Method: v1.MethodConnectionConnect, Params: params}); err != nil {
		t.Fatal(err)
	}
	response, err := ipc.ReadResponse(client)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	if response.Error != nil {
		t.Fatalf("connection response error = %#v", response.Error)
	}
	var connection v1.Connection
	if err := json.Unmarshal(response.Result, &connection); err != nil {
		t.Fatal(err)
	}
	if connection.DeviceID != destinationID || connection.Path != v1.ConnectionPathDirect {
		t.Fatalf("connection = %#v", connection)
	}

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if handle.closeCount() != 1 {
		t.Fatalf("close count = %d, want 1", handle.closeCount())
	}
}

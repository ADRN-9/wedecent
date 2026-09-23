package coreapi

import (
	"bytes"
	"context"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/coreapi/localserver"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestTerminalServiceIdleReadReturnsBeforeLocalServerDeadline(t *testing.T) {
	if terminalReadWait >= localserver.DefaultRequestTimeout {
		t.Fatalf("terminal read wait %s must stay below local server request timeout %s", terminalReadWait, localserver.DefaultRequestTimeout)
	}

	handle := newFakeTerminalConnectionHandle()
	backend := &fakeConnectionBackend{opened: OpenedConnection{
		Path:   v1.ConnectionPathRelay,
		Handle: handle,
	}}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x53}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	result, err := service.ReadTerminal(context.Background(), v1.TerminalReadRequest{
		ConnectionID: connection.ID,
		MaxBytes:     v1.MaxTerminalChunkBytes,
	})
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 0 || result.Closed {
		t.Fatalf("idle read = %#v, want empty still-open result", result)
	}
	if elapsed >= localserver.DefaultRequestTimeout {
		t.Fatalf("idle read took %s, local server timeout is %s", elapsed, localserver.DefaultRequestTimeout)
	}
}

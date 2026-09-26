package desktopbridge

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeTerminalSource struct {
	connection v1.Connection
	read       v1.TerminalReadResult
	connectReq v1.ConnectRequest
	writeReq   v1.TerminalWriteRequest
	resizeReq  v1.TerminalResizeRequest
	disconnect v1.DisconnectRequest
	err        error
}

func (f *fakeTerminalSource) Connect(_ context.Context, req v1.ConnectRequest) (v1.Connection, error) {
	f.connectReq = req
	return f.connection, f.err
}

func (f *fakeTerminalSource) Disconnect(_ context.Context, req v1.DisconnectRequest) error {
	f.disconnect = req
	return f.err
}

func (f *fakeTerminalSource) ReadTerminal(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	return f.read, f.err
}

func (f *fakeTerminalSource) WriteTerminal(_ context.Context, req v1.TerminalWriteRequest) error {
	f.writeReq = req
	return f.err
}

func (f *fakeTerminalSource) ResizeTerminal(_ context.Context, req v1.TerminalResizeRequest) error {
	f.resizeReq = req
	return f.err
}

func TestConnectReturnsSanitizedConnectionSummary(t *testing.T) {
	source := &fakeTerminalSource{connection: v1.Connection{
		ID:       "conn_0123456789abcdef",
		DeviceID: "wd_0123456789abcdef",
		State:    v1.ConnectionStateConnected,
		Path:     v1.ConnectionPathLAN,
	}}
	got, err := Connect(context.Background(), source, "wd_0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != source.connection.ID || got.DeviceID != source.connection.DeviceID || got.Path != v1.ConnectionPathLAN {
		t.Fatalf("Connect() = %#v", got)
	}
	if source.connectReq.OperationID != "" {
		t.Fatalf("renderer-controlled operation id escaped bridge: %q", source.connectReq.OperationID)
	}
}

func TestConnectRejectsMismatchedCoreDevice(t *testing.T) {
	source := &fakeTerminalSource{connection: v1.Connection{
		ID:       "conn_0123456789abcdef",
		DeviceID: "wd_fedcba9876543210",
		State:    v1.ConnectionStateConnected,
		Path:     v1.ConnectionPathDirect,
	}}
	_, err := Connect(context.Background(), source, "wd_0123456789abcdef")
	if !errors.Is(err, ErrInvalidTerminalBridgeRequest) {
		t.Fatalf("Connect() error = %v", err)
	}
}

func TestWriteTerminalEnforcesBoundAndDoesNotAcceptOperationID(t *testing.T) {
	source := &fakeTerminalSource{}
	data := []byte("hello")
	if err := WriteTerminal(context.Background(), source, "conn_abc", data); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source.writeReq.Data, data) || source.writeReq.OperationID != "" {
		t.Fatalf("write request = %#v", source.writeReq)
	}
	for _, data := range [][]byte{nil, bytes.Repeat([]byte{'x'}, v1.MaxTerminalChunkBytes+1)} {
		if err := WriteTerminal(context.Background(), source, "conn_abc", data); !errors.Is(err, ErrInvalidTerminalBridgeRequest) {
			t.Fatalf("WriteTerminal(%d bytes) error = %v", len(data), err)
		}
	}
}

func TestReadTerminalRejectsOversizedCoreOutput(t *testing.T) {
	source := &fakeTerminalSource{read: v1.TerminalReadResult{Data: bytes.Repeat([]byte{'x'}, v1.MaxTerminalChunkBytes+1)}}
	if _, err := ReadTerminal(context.Background(), source, "conn_abc"); !errors.Is(err, ErrInvalidTerminalBridgeRequest) {
		t.Fatalf("ReadTerminal() error = %v", err)
	}
}

func TestResizeAndDisconnectForwardOnlyConnectionID(t *testing.T) {
	source := &fakeTerminalSource{}
	if err := ResizeTerminal(context.Background(), source, "conn_abc", 120, 40); err != nil {
		t.Fatal(err)
	}
	if source.resizeReq.ConnectionID != "conn_abc" || source.resizeReq.Cols != 120 || source.resizeReq.Rows != 40 {
		t.Fatalf("resize request = %#v", source.resizeReq)
	}
	if err := Disconnect(context.Background(), source, "conn_abc"); err != nil {
		t.Fatal(err)
	}
	if source.disconnect.ConnectionID != "conn_abc" {
		t.Fatalf("disconnect request = %#v", source.disconnect)
	}
}

func TestTerminalBridgeRejectsInvalidPublicIDsAndDimensions(t *testing.T) {
	source := &fakeTerminalSource{}
	badIDs := []string{"", "contains space", "line\nbreak", strings.Repeat("x", MaxDesktopIDBytes+1)}
	for _, id := range badIDs {
		if _, err := Connect(context.Background(), source, id); !errors.Is(err, ErrInvalidTerminalBridgeRequest) {
			t.Fatalf("Connect(%q) error = %v", id, err)
		}
	}
	if err := ResizeTerminal(context.Background(), source, "conn_abc", 0, 24); !errors.Is(err, ErrInvalidTerminalBridgeRequest) {
		t.Fatalf("ResizeTerminal zero cols error = %v", err)
	}
}

package client

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type scriptedDialer struct {
	t        *testing.T
	mu       sync.Mutex
	handlers []func(net.Conn)
	calls    int
}

func (d *scriptedDialer) Dial(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.calls >= len(d.handlers) {
		d.mu.Unlock()
		return nil, errors.New("unexpected dial")
	}
	handler := d.handlers[d.calls]
	d.calls++
	d.mu.Unlock()

	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		handler(serverConn)
	}()
	return clientConn, nil
}

func (d *scriptedDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func TestClientTypedCallsUseOneConnectionEach(t *testing.T) {
	status := v1.Status{
		APIVersion: v1.Version,
		SignedIn:   true,
		UserID:     "user-1",
		Email:      "person@example.test",
		DeviceID:   "wd_local000000000",
		DeviceName: "local",
	}
	devices := []v1.Device{{ID: "wd_peer0000000000", Name: "peer", Fingerprint: "AA:BB"}}

	dialer := &scriptedDialer{t: t, handlers: []func(net.Conn){
		func(conn net.Conn) {
			req, err := ipc.ReadRequest(conn)
			if err != nil {
				t.Errorf("read status request: %v", err)
				return
			}
			if req.Method != v1.MethodStatusGet || len(req.Params) != 0 {
				t.Errorf("status request = %#v", req)
			}
			result, _ := ipc.MarshalResult(status)
			if err := ipc.WriteResponse(conn, ipc.Response{Version: v1.Version, ID: req.ID, Result: result}); err != nil {
				t.Errorf("write status response: %v", err)
			}
		},
		func(conn net.Conn) {
			req, err := ipc.ReadRequest(conn)
			if err != nil {
				t.Errorf("read devices request: %v", err)
				return
			}
			if req.Method != v1.MethodDevicesList || len(req.Params) != 0 {
				t.Errorf("devices request = %#v", req)
			}
			result, _ := ipc.MarshalResult(devices)
			if err := ipc.WriteResponse(conn, ipc.Response{Version: v1.Version, ID: req.ID, Result: result}); err != nil {
				t.Errorf("write devices response: %v", err)
			}
		},
	}}
	client, err := New(Config{
		Dial:    dialer.Dial,
		Timeout: time.Second,
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x31}, 36)),
	})
	if err != nil {
		t.Fatal(err)
	}

	gotStatus, err := client.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotStatus != status {
		t.Fatalf("status = %#v, want %#v", gotStatus, status)
	}
	gotDevices, err := client.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(gotDevices) != 1 || gotDevices[0] != devices[0] {
		t.Fatalf("devices = %#v, want %#v", gotDevices, devices)
	}
	if dialer.callCount() != 2 {
		t.Fatalf("dial calls = %d, want 2", dialer.callCount())
	}
}

func TestClientTerminalWriteUsesOpaqueConnectionID(t *testing.T) {
	input := []byte("echo hello\n")
	dialer := &scriptedDialer{t: t, handlers: []func(net.Conn){func(conn net.Conn) {
		req, err := ipc.ReadRequest(conn)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		if req.Method != v1.MethodTerminalWrite {
			t.Errorf("method = %q", req.Method)
		}
		var params v1.TerminalWriteRequest
		if err := ipc.DecodeParams(req.Params, &params); err != nil {
			t.Errorf("decode params: %v", err)
			return
		}
		if params.ConnectionID != "conn_abcdefghijklmnopqrstuvwx" || string(params.Data) != string(input) {
			t.Errorf("params = %#v", params)
		}
		result, _ := ipc.MarshalResult(nil)
		_ = ipc.WriteResponse(conn, ipc.Response{Version: v1.Version, ID: req.ID, Result: result})
	}}}
	client, err := New(Config{Dial: dialer.Dial, Timeout: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{0x44}, 18))})
	if err != nil {
		t.Fatal(err)
	}

	if err := client.WriteTerminal(context.Background(), v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         input,
	}); err != nil {
		t.Fatal(err)
	}
	if string(input) != "echo hello\n" {
		t.Fatalf("caller input was mutated: %q", input)
	}
}

func TestClientReturnsStableRemoteError(t *testing.T) {
	dialer := &scriptedDialer{t: t, handlers: []func(net.Conn){func(conn net.Conn) {
		req, err := ipc.ReadRequest(conn)
		if err != nil {
			return
		}
		_ = ipc.WriteResponse(conn, ipc.Response{
			Version: v1.Version,
			ID:      req.ID,
			Error:   &ipc.ResponseError{Code: "connection_not_found", Message: "connection not found"},
		})
	}}}
	client, err := New(Config{Dial: dialer.Dial, Timeout: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{0x55}, 18))})
	if err != nil {
		t.Fatal(err)
	}

	err = client.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: "conn_abcdefghijklmnopqrstuvwx"})
	var remote *RemoteError
	if !errors.As(err, &remote) || !remote.IsCode("connection_not_found") || remote.Message != "connection not found" {
		t.Fatalf("error = %#v", err)
	}
}

func TestClientRejectsMismatchedResponseID(t *testing.T) {
	dialer := &scriptedDialer{t: t, handlers: []func(net.Conn){func(conn net.Conn) {
		if _, err := ipc.ReadRequest(conn); err != nil {
			return
		}
		result, _ := ipc.MarshalResult(v1.Status{APIVersion: v1.Version})
		_ = ipc.WriteResponse(conn, ipc.Response{Version: v1.Version, ID: "wrong-id", Result: result})
	}}}
	client, err := New(Config{Dial: dialer.Dial, Timeout: time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{0x66}, 18))})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.GetStatus(context.Background())
	if !errors.Is(err, ErrMismatchedResponse) {
		t.Fatalf("error = %v, want mismatched response", err)
	}
}

func TestClientCancellationUnblocksResponseRead(t *testing.T) {
	requestRead := make(chan struct{})
	release := make(chan struct{})
	dialer := &scriptedDialer{t: t, handlers: []func(net.Conn){func(conn net.Conn) {
		if _, err := ipc.ReadRequest(conn); err != nil {
			return
		}
		close(requestRead)
		<-release
	}}}
	client, err := New(Config{Dial: dialer.Dial, Timeout: 5 * time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 18))})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.GetStatus(ctx)
		done <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client read did not unblock after cancellation")
	}
	close(release)
}

func TestClientRejectsExcessiveTimeout(t *testing.T) {
	if _, err := New(Config{Timeout: maxTimeout + time.Nanosecond}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want invalid config", err)
	}
}

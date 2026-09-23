package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeTerminalService struct {
	readResult v1.TerminalReadResult
	readErr    error
	writeErr   error
	resizeErr  error
	readReq    v1.TerminalReadRequest
	writeReq   v1.TerminalWriteRequest
	resizeReq  v1.TerminalResizeRequest
}

func (f *fakeTerminalService) ReadTerminal(_ context.Context, req v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	f.readReq = req
	return f.readResult, f.readErr
}

func (f *fakeTerminalService) WriteTerminal(_ context.Context, req v1.TerminalWriteRequest) error {
	f.writeReq = req
	f.writeReq.Data = append([]byte(nil), req.Data...)
	return f.writeErr
}

func (f *fakeTerminalService) ResizeTerminal(_ context.Context, req v1.TerminalResizeRequest) error {
	f.resizeReq = req
	return f.resizeErr
}

func TestServerTerminalReadWriteResize(t *testing.T) {
	read := &fakeReadService{}
	terminal := &fakeTerminalService{readResult: v1.TerminalReadResult{
		Data: []byte{0, 1, 2, 3},
	}}
	server, err := NewServerWithServices(Services{
		Status:   read,
		Devices:  read,
		Terminal: terminal,
	})
	if err != nil {
		t.Fatal(err)
	}

	readParams, _ := json.Marshal(v1.TerminalReadRequest{ConnectionID: "conn_abcdefghijklmnopqrstuvwx", MaxBytes: 1024})
	response := serve(t, server, Request{Version: v1.Version, ID: "terminal-read", Method: v1.MethodTerminalRead, Params: readParams})
	if response.Error != nil {
		t.Fatalf("read response error = %#v", response.Error)
	}
	var readResult v1.TerminalReadResult
	if err := json.Unmarshal(response.Result, &readResult); err != nil {
		t.Fatal(err)
	}
	if string(readResult.Data) != string([]byte{0, 1, 2, 3}) || terminal.readReq.MaxBytes != 1024 {
		t.Fatalf("read result=%#v request=%#v", readResult, terminal.readReq)
	}

	writeParams, _ := json.Marshal(v1.TerminalWriteRequest{ConnectionID: "conn_abcdefghijklmnopqrstuvwx", Data: []byte("secret input\n")})
	response = serve(t, server, Request{Version: v1.Version, ID: "terminal-write", Method: v1.MethodTerminalWrite, Params: writeParams})
	if response.Error != nil {
		t.Fatalf("write response error = %#v", response.Error)
	}
	if string(terminal.writeReq.Data) != "secret input\n" {
		t.Fatalf("write request data = %q", terminal.writeReq.Data)
	}

	resizeParams, _ := json.Marshal(v1.TerminalResizeRequest{ConnectionID: "conn_abcdefghijklmnopqrstuvwx", Cols: 132, Rows: 43})
	response = serve(t, server, Request{Version: v1.Version, ID: "terminal-resize", Method: v1.MethodTerminalResize, Params: resizeParams})
	if response.Error != nil {
		t.Fatalf("resize response error = %#v", response.Error)
	}
	if terminal.resizeReq.Cols != 132 || terminal.resizeReq.Rows != 43 {
		t.Fatalf("resize request = %#v", terminal.resizeReq)
	}
}

func TestServerTerminalMethodsFailClosedWhenUncomposed(t *testing.T) {
	read := &fakeReadService{}
	server, err := NewServer(read, read)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(v1.TerminalReadRequest{ConnectionID: "conn_abcdefghijklmnopqrstuvwx"})
	response := serve(t, server, Request{Version: v1.Version, ID: "terminal-missing", Method: v1.MethodTerminalRead, Params: params})
	if response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("response = %#v", response)
	}
}

func TestServerTerminalStrictParamsAndErrorMapping(t *testing.T) {
	read := &fakeReadService{}
	terminal := &fakeTerminalService{writeErr: coreapi.ErrTerminalUnavailable}
	server, err := NewServerWithServices(Services{Status: read, Devices: read, Terminal: terminal})
	if err != nil {
		t.Fatal(err)
	}

	bad := serve(t, server, Request{
		Version: v1.Version,
		ID:      "terminal-bad",
		Method:  v1.MethodTerminalResize,
		Params:  json.RawMessage(`{"connection_id":"conn_abcdefghijklmnopqrstuvwx","cols":80,"rows":24,"extra":true}`),
	})
	if bad.Error == nil || bad.Error.Code != ErrorInvalidParams {
		t.Fatalf("bad params response = %#v", bad)
	}

	params, _ := json.Marshal(v1.TerminalWriteRequest{ConnectionID: "conn_abcdefghijklmnopqrstuvwx", Data: []byte("x")})
	response := serve(t, server, Request{Version: v1.Version, ID: "terminal-error", Method: v1.MethodTerminalWrite, Params: params})
	if response.Error == nil || response.Error.Code != ErrorTerminalUnavailable {
		t.Fatalf("terminal error response = %#v", response)
	}

	terminal.writeErr = errors.New("private transport detail")
	response = serve(t, server, Request{Version: v1.Version, ID: "terminal-redact", Method: v1.MethodTerminalWrite, Params: params})
	if response.Error == nil || response.Error.Code != ErrorInternal || response.Error.Message != "internal error" {
		t.Fatalf("redaction response = %#v", response)
	}
}

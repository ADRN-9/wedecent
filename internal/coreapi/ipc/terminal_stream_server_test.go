package ipc

import (
	"context"
	"encoding/json"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type terminalStreamIPCService struct {
	opened v1.TerminalStream
	wrote  v1.TerminalStreamWriteRequest
}

func (s *terminalStreamIPCService) ReadTerminal(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	return v1.TerminalReadResult{}, nil
}
func (s *terminalStreamIPCService) WriteTerminal(context.Context, v1.TerminalWriteRequest) error {
	return nil
}
func (s *terminalStreamIPCService) ResizeTerminal(context.Context, v1.TerminalResizeRequest) error {
	return nil
}
func (s *terminalStreamIPCService) OpenTerminalStream(context.Context, v1.TerminalStreamOpenRequest) (v1.TerminalStream, error) {
	return s.opened, nil
}
func (s *terminalStreamIPCService) CloseTerminalStream(context.Context, v1.TerminalStreamCloseRequest) error {
	return nil
}
func (s *terminalStreamIPCService) ReadTerminalStream(context.Context, v1.TerminalStreamReadRequest) (v1.TerminalReadResult, error) {
	return v1.TerminalReadResult{Data: []byte("ok")}, nil
}
func (s *terminalStreamIPCService) WriteTerminalStream(_ context.Context, req v1.TerminalStreamWriteRequest) error {
	s.wrote = req
	return nil
}
func (s *terminalStreamIPCService) ResizeTerminalStream(context.Context, v1.TerminalStreamResizeRequest) error {
	return nil
}

func TestHandleTerminalStreamDispatchesOpaqueCoreOperation(t *testing.T) {
	service := &terminalStreamIPCService{opened: v1.TerminalStream{ID: "term_opaque", ConnectionID: "conn_parent"}}
	server := &Server{terminal: service}
	params, err := json.Marshal(v1.TerminalStreamOpenRequest{ConnectionID: "conn_parent", Cols: 80, Rows: 24, Term: "xterm-256color"})
	if err != nil {
		t.Fatal(err)
	}
	response, handled := server.handleTerminalStream(context.Background(), Request{
		Version: v1.Version, ID: "req_test", Method: v1.MethodTerminalStreamOpen, Params: params,
	}, Response{Version: v1.Version, ID: "req_test"})
	if !handled || response.Error != nil {
		t.Fatalf("handled=%v error=%v", handled, response.Error)
	}
	var stream v1.TerminalStream
	if err := json.Unmarshal(response.Result, &stream); err != nil {
		t.Fatal(err)
	}
	if stream != service.opened {
		t.Fatalf("stream = %#v, want %#v", stream, service.opened)
	}
}

func TestHandleTerminalStreamRejectsUnknownWriteField(t *testing.T) {
	server := &Server{terminal: &terminalStreamIPCService{}}
	params := json.RawMessage(`{"connection_id":"conn_parent","terminal_id":"term_child","data":"eA==","endpoint":"forbidden"}`)
	response, handled := server.handleTerminalStream(context.Background(), Request{
		Version: v1.Version, ID: "req_test", Method: v1.MethodTerminalStreamWrite, Params: params,
	}, Response{Version: v1.Version, ID: "req_test"})
	if !handled || response.Error == nil || response.Error.Code != ErrorInvalidParams {
		t.Fatalf("response = %#v handled=%v", response, handled)
	}
}

func TestHandleTerminalStreamFailsClosedWithoutStreamCapability(t *testing.T) {
	server := &Server{terminal: terminalOnlyIPCService{}}
	response, handled := server.handleTerminalStream(context.Background(), Request{
		Version: v1.Version, ID: "req_test", Method: v1.MethodTerminalStreamOpen, Params: json.RawMessage(`{}`),
	}, Response{Version: v1.Version, ID: "req_test"})
	if !handled || response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("response = %#v handled=%v", response, handled)
	}
}

type terminalOnlyIPCService struct{}

func (terminalOnlyIPCService) ReadTerminal(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	return v1.TerminalReadResult{}, nil
}
func (terminalOnlyIPCService) WriteTerminal(context.Context, v1.TerminalWriteRequest) error {
	return nil
}
func (terminalOnlyIPCService) ResizeTerminal(context.Context, v1.TerminalResizeRequest) error {
	return nil
}

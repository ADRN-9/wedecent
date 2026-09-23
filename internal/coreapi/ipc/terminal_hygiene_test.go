package ipc

import (
	"context"
	"encoding/json"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestServerTerminalWriteWipesParams(t *testing.T) {
	read := &fakeReadService{}
	terminal := &fakeTerminalService{}
	server, err := NewServerWithServices(Services{
		Status:   read,
		Devices:  read,
		Terminal: terminal,
	})
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"connection_id":"conn_abcdefghijklmnopqrstuvwx","data":"c2VjcmV0LWlucHV0"}`)
	response := server.handle(context.Background(), Request{
		Version: v1.Version,
		ID:      "terminal-wipe",
		Method:  v1.MethodTerminalWrite,
		Params:  params,
	})
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}
	if string(terminal.writeReq.Data) != "secret-input" {
		t.Fatalf("dispatched terminal input = %q", terminal.writeReq.Data)
	}
	for i, b := range params {
		if b != 0 {
			t.Fatalf("params byte %d was not wiped", i)
		}
	}
}

func TestServerTerminalWriteUnavailableWipesParams(t *testing.T) {
	read := &fakeReadService{}
	server, err := NewServer(read, read)
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"connection_id":"conn_abcdefghijklmnopqrstuvwx","data":"c2VjcmV0LWlucHV0"}`)
	response := server.handle(context.Background(), Request{
		Version: v1.Version,
		ID:      "terminal-wipe-unavailable",
		Method:  v1.MethodTerminalWrite,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("response = %#v", response)
	}
	for i, b := range params {
		if b != 0 {
			t.Fatalf("params byte %d was not wiped", i)
		}
	}
}

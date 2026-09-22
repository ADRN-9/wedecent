package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeConnectionIPCService struct {
	connection    v1.Connection
	connectReq    v1.ConnectRequest
	disconnectReq v1.DisconnectRequest
	connectErr    error
	disconnectErr error
}

func (f *fakeConnectionIPCService) Connect(_ context.Context, req v1.ConnectRequest) (v1.Connection, error) {
	f.connectReq = req
	return f.connection, f.connectErr
}

func (f *fakeConnectionIPCService) Disconnect(_ context.Context, req v1.DisconnectRequest) error {
	f.disconnectReq = req
	return f.disconnectErr
}

func TestServerConnectionMethodsDispatchStrictly(t *testing.T) {
	read := &fakeReadService{}
	connections := &fakeConnectionIPCService{connection: v1.Connection{
		ID:       "conn_test",
		DeviceID: "wd_dest0000000000",
		State:    v1.ConnectionStateConnected,
		Path:     v1.ConnectionPathRelay,
	}}
	server, err := NewServerWithServices(Services{
		Status:      read,
		Devices:     read,
		Connections: connections,
	})
	if err != nil {
		t.Fatal(err)
	}

	connectParams, err := json.Marshal(v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "connect-1",
		Method:  v1.MethodConnectionConnect,
		Params:  connectParams,
	})
	if response.Error != nil {
		t.Fatalf("connect response error = %#v", response.Error)
	}
	if connections.connectReq.DeviceID != "wd_dest0000000000" {
		t.Fatalf("connect request = %#v", connections.connectReq)
	}
	var connection v1.Connection
	if err := json.Unmarshal(response.Result, &connection); err != nil {
		t.Fatal(err)
	}
	if connection.ID != "conn_test" || connection.Path != v1.ConnectionPathRelay {
		t.Fatalf("connection = %#v", connection)
	}

	disconnectParams, err := json.Marshal(v1.DisconnectRequest{ConnectionID: "conn_test"})
	if err != nil {
		t.Fatal(err)
	}
	response = serve(t, server, Request{
		Version: v1.Version,
		ID:      "disconnect-1",
		Method:  v1.MethodConnectionDisconnect,
		Params:  disconnectParams,
	})
	if response.Error != nil {
		t.Fatalf("disconnect response error = %#v", response.Error)
	}
	if connections.disconnectReq.ConnectionID != "conn_test" {
		t.Fatalf("disconnect request = %#v", connections.disconnectReq)
	}

	bad := serve(t, server, Request{
		Version: v1.Version,
		ID:      "connect-bad",
		Method:  v1.MethodConnectionConnect,
		Params:  json.RawMessage(`{"device_id":"wd_dest0000000000","unexpected":true}`),
	})
	if bad.Error == nil || bad.Error.Code != ErrorInvalidParams {
		t.Fatalf("bad connect response = %#v", bad)
	}
}

func TestServerMapsConnectionErrorsWithoutLeakingBackendDetails(t *testing.T) {
	read := &fakeReadService{}
	connections := &fakeConnectionIPCService{}
	server, err := NewServerWithServices(Services{
		Status:      read,
		Devices:     read,
		Connections: connections,
	})
	if err != nil {
		t.Fatal(err)
	}
	connectParams, err := json.Marshal(v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"invalid":     {err: coreapi.ErrInvalidConnectionRequest, code: ErrorInvalidParams},
		"limit":       {err: coreapi.ErrConnectionLimit, code: ErrorConnectionLimit},
		"unavailable": {err: coreapi.ErrConnectionServiceClosed, code: ErrorConnectionUnavailable},
		"failed":      {err: errors.Join(coreapi.ErrConnectionOperation, errors.New("secret backend detail")), code: ErrorConnectionFailed},
	} {
		t.Run(name, func(t *testing.T) {
			connections.connectErr = tc.err
			response := serve(t, server, Request{
				Version: v1.Version,
				ID:      "connect-error",
				Method:  v1.MethodConnectionConnect,
				Params:  connectParams,
			})
			if response.Error == nil || response.Error.Code != tc.code {
				t.Fatalf("response = %#v, want code %q", response, tc.code)
			}
			data, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) == "" || strings.Contains(string(data), "secret backend detail") {
				t.Fatalf("response leaked backend detail: %s", data)
			}
		})
	}

	connections.connectErr = nil
	connections.disconnectErr = coreapi.ErrConnectionNotFound
	disconnectParams, err := json.Marshal(v1.DisconnectRequest{ConnectionID: "conn_missing"})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "disconnect-missing",
		Method:  v1.MethodConnectionDisconnect,
		Params:  disconnectParams,
	})
	if response.Error == nil || response.Error.Code != ErrorConnectionNotFound {
		t.Fatalf("disconnect response = %#v", response)
	}
}

func TestServerConnectionMethodsAreUnavailableWithoutService(t *testing.T) {
	read := &fakeReadService{}
	server, err := NewServer(read, read)
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "connect-disabled",
		Method:  v1.MethodConnectionConnect,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("response = %#v", response)
	}
}

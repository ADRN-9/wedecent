package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeReadService struct {
	status    v1.Status
	devices   []v1.Device
	getDevice v1.Device
	statusErr error
	listErr   error
	getErr    error
}

func (f *fakeReadService) GetStatus(context.Context) (v1.Status, error) {
	return f.status, f.statusErr
}

func (f *fakeReadService) ListDevices(context.Context) ([]v1.Device, error) {
	return f.devices, f.listErr
}

func (f *fakeReadService) GetDevice(context.Context, v1.GetDeviceRequest) (v1.Device, error) {
	return f.getDevice, f.getErr
}

func TestServerStatusRoundTrip(t *testing.T) {
	service := &fakeReadService{status: v1.Status{
		APIVersion: v1.Version,
		SignedIn:   true,
		UserID:     "user-1",
		Email:      "person@example.test",
		DeviceID:   "wd_aaaaaaaaaaaaaaaa",
		DeviceName: "local",
	}}
	server, err := NewServer(service, service)
	if err != nil {
		t.Fatal(err)
	}

	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "request-1",
		Method:  v1.MethodStatusGet,
	})
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}
	var status v1.Status
	if err := json.Unmarshal(response.Result, &status); err != nil {
		t.Fatal(err)
	}
	if status != service.status {
		t.Fatalf("status = %#v, want %#v", status, service.status)
	}
}

func TestServerDeviceGetDecodesStrictParams(t *testing.T) {
	service := &fakeReadService{getDevice: v1.Device{ID: "wd_aaaaaaaaaaaaaaaa", Name: "alpha"}}
	server, err := NewServer(service, service)
	if err != nil {
		t.Fatal(err)
	}

	params, err := json.Marshal(v1.GetDeviceRequest{DeviceID: service.getDevice.ID})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "request-2",
		Method:  v1.MethodDeviceGet,
		Params:  params,
	})
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}

	badResponse := serve(t, server, Request{
		Version: v1.Version,
		ID:      "request-3",
		Method:  v1.MethodDeviceGet,
		Params:  json.RawMessage(`{"device_id":"wd_aaaaaaaaaaaaaaaa","unexpected":true}`),
	})
	if badResponse.Error == nil || badResponse.Error.Code != ErrorInvalidParams {
		t.Fatalf("bad params response = %#v", badResponse)
	}
}

func TestServerMapsKnownErrors(t *testing.T) {
	service := &fakeReadService{getErr: coreapi.ErrDeviceNotFound}
	server, err := NewServer(service, service)
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(v1.GetDeviceRequest{DeviceID: "wd_missing00000000"})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "request-4",
		Method:  v1.MethodDeviceGet,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorDeviceNotFound {
		t.Fatalf("response = %#v", response)
	}
}

func TestServerDoesNotLeakInternalErrors(t *testing.T) {
	service := &fakeReadService{statusErr: errors.New("top-secret-token-value")}
	server, err := NewServer(service, service)
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "request-5",
		Method:  v1.MethodStatusGet,
	})
	if response.Error == nil || response.Error.Code != ErrorInternal {
		t.Fatalf("response = %#v", response)
	}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "top-secret") {
		t.Fatalf("response leaked backend error: %s", data)
	}
}

func TestServerRejectsUnknownMethodWithoutDispatch(t *testing.T) {
	service := &fakeReadService{}
	server, err := NewServer(service, service)
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "request-6",
		Method:  "unknown.method",
	})
	if response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("response = %#v", response)
	}
}

func TestServerMapsCanceledServiceRequest(t *testing.T) {
	service := &fakeReadService{listErr: context.Canceled}
	server, err := NewServer(service, service)
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "request-7",
		Method:  v1.MethodDevicesList,
	})
	if response.Error == nil || response.Error.Code != ErrorRequestCanceled {
		t.Fatalf("response = %#v", response)
	}
}

func TestServerFallsBackWhenResponseExceedsFrameLimit(t *testing.T) {
	service := &fakeReadService{devices: []v1.Device{{
		ID:   "wd_aaaaaaaaaaaaaaaa",
		Name: string(bytes.Repeat([]byte("x"), MaxFrameBytes)),
	}}}
	server, err := NewServer(service, service)
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "request-8",
		Method:  v1.MethodDevicesList,
	})
	if response.Error == nil || response.Error.Code != ErrorInternal {
		t.Fatalf("response = %#v", response)
	}
}

func TestNewServerRequiresCapabilities(t *testing.T) {
	service := &fakeReadService{}
	if _, err := NewServer(nil, service); err == nil {
		t.Fatal("NewServer(nil status) succeeded")
	}
	if _, err := NewServer(service, nil); err == nil {
		t.Fatal("NewServer(nil devices) succeeded")
	}
}

func serve(t *testing.T, server *Server, req Request) Response {
	t.Helper()
	var wire bytes.Buffer
	if err := WriteRequest(&wire, req); err != nil {
		t.Fatal(err)
	}
	if err := server.ServeOne(context.Background(), &wire); err != nil {
		t.Fatal(err)
	}
	response, err := ReadResponse(&wire)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

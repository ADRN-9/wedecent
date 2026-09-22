package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeNetworkService struct {
	transports    []v1.TransportStatus
	route         v1.RouteStatus
	transportsErr error
	routeErr      error
}

func (f *fakeNetworkService) GetTransportStatus(context.Context) ([]v1.TransportStatus, error) {
	return f.transports, f.transportsErr
}

func (f *fakeNetworkService) GetRouteStatus(context.Context, v1.GetRouteStatusRequest) (v1.RouteStatus, error) {
	return f.route, f.routeErr
}

func TestServerTransportStatusRoundTrip(t *testing.T) {
	read := &fakeReadService{}
	network := &fakeNetworkService{transports: []v1.TransportStatus{
		{Name: v1.TransportLAN, Available: true},
		{Name: v1.TransportInternet, Available: true},
		{Name: v1.TransportBluetooth, Available: false},
	}}
	server, err := NewServerWithServices(Services{
		Status: read, Devices: read, Transports: network, Routes: network,
	})
	if err != nil {
		t.Fatal(err)
	}

	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "network-1",
		Method:  v1.MethodTransportsList,
	})
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}
	var got []v1.TransportStatus
	if err := json.Unmarshal(response.Result, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != v1.TransportLAN || !got[0].Available {
		t.Fatalf("transport status = %#v", got)
	}

	bad := serve(t, server, Request{
		Version: v1.Version,
		ID:      "network-2",
		Method:  v1.MethodTransportsList,
		Params:  json.RawMessage(`{"unexpected":true}`),
	})
	if bad.Error == nil || bad.Error.Code != ErrorInvalidParams {
		t.Fatalf("bad transport params response = %#v", bad)
	}
}

func TestServerRouteStatusUsesStrictParamsAndMapsNotFound(t *testing.T) {
	read := &fakeReadService{}
	network := &fakeNetworkService{route: v1.RouteStatus{
		ConnectionID:  "connection-1",
		DestinationID: "wd_dest0000000000",
		Path:          v1.ConnectionPathRelay,
	}}
	server, err := NewServerWithServices(Services{
		Status: read, Devices: read, Transports: network, Routes: network,
	})
	if err != nil {
		t.Fatal(err)
	}

	params, err := json.Marshal(v1.GetRouteStatusRequest{ConnectionID: "connection-1"})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "route-1",
		Method:  v1.MethodRouteGet,
		Params:  params,
	})
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}
	var got v1.RouteStatus
	if err := json.Unmarshal(response.Result, &got); err != nil {
		t.Fatal(err)
	}
	if got.ConnectionID != "connection-1" || got.Path != v1.ConnectionPathRelay {
		t.Fatalf("route status = %#v", got)
	}

	bad := serve(t, server, Request{
		Version: v1.Version,
		ID:      "route-2",
		Method:  v1.MethodRouteGet,
		Params:  json.RawMessage(`{"connection_id":"connection-1","unexpected":true}`),
	})
	if bad.Error == nil || bad.Error.Code != ErrorInvalidParams {
		t.Fatalf("bad route params response = %#v", bad)
	}

	network.routeErr = coreapi.ErrRouteNotFound
	missing := serve(t, server, Request{
		Version: v1.Version,
		ID:      "route-3",
		Method:  v1.MethodRouteGet,
		Params:  params,
	})
	if missing.Error == nil || missing.Error.Code != ErrorRouteNotFound {
		t.Fatalf("missing route response = %#v", missing)
	}
}

func TestServerMapsInvalidRouteQueryToInvalidParams(t *testing.T) {
	read := &fakeReadService{}
	network := &fakeNetworkService{routeErr: coreapi.ErrInvalidRouteRequest}
	server, err := NewServerWithServices(Services{
		Status: read, Devices: read, Routes: network,
	})
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(v1.GetRouteStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "route-invalid",
		Method:  v1.MethodRouteGet,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorInvalidParams {
		t.Fatalf("response = %#v", response)
	}
}

func TestServerNetworkMethodsFailClosedWhenCapabilityIsAbsent(t *testing.T) {
	read := &fakeReadService{}
	server, err := NewServer(read, read)
	if err != nil {
		t.Fatal(err)
	}

	transportResponse := serve(t, server, Request{
		Version: v1.Version,
		ID:      "network-disabled",
		Method:  v1.MethodTransportsList,
	})
	if transportResponse.Error == nil || transportResponse.Error.Code != ErrorMethodNotFound {
		t.Fatalf("transport response = %#v", transportResponse)
	}

	params, err := json.Marshal(v1.GetRouteStatusRequest{ConnectionID: "connection-1"})
	if err != nil {
		t.Fatal(err)
	}
	routeResponse := serve(t, server, Request{
		Version: v1.Version,
		ID:      "route-disabled",
		Method:  v1.MethodRouteGet,
		Params:  params,
	})
	if routeResponse.Error == nil || routeResponse.Error.Code != ErrorMethodNotFound {
		t.Fatalf("route response = %#v", routeResponse)
	}
}

func TestServerMapsNetworkCancellation(t *testing.T) {
	read := &fakeReadService{}
	network := &fakeNetworkService{transportsErr: context.Canceled, routeErr: errors.New("unused")}
	server, err := NewServerWithServices(Services{
		Status: read, Devices: read, Transports: network,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "network-canceled",
		Method:  v1.MethodTransportsList,
	})
	if response.Error == nil || response.Error.Code != ErrorRequestCanceled {
		t.Fatalf("response = %#v", response)
	}
}

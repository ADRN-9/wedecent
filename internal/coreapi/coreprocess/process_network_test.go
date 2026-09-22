package coreprocess

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/identity"
)

func TestOpenReadOnlyExposesTransportAndRouteReaders(t *testing.T) {
	dir := t.TempDir()
	if _, err := identity.Ensure(dir, "core-network-test"); err != nil {
		t.Fatal(err)
	}
	server, err := OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}

	transportResponse := coreRequest(t, server, ipc.Request{
		Version: v1.Version,
		ID:      "network-1",
		Method:  v1.MethodTransportsList,
	})
	if transportResponse.Error != nil {
		t.Fatalf("transport response error = %#v", transportResponse.Error)
	}
	var transports []v1.TransportStatus
	if err := json.Unmarshal(transportResponse.Result, &transports); err != nil {
		t.Fatal(err)
	}
	if len(transports) != 3 ||
		transports[0].Name != v1.TransportLAN || !transports[0].Available ||
		transports[1].Name != v1.TransportInternet || !transports[1].Available ||
		transports[2].Name != v1.TransportBluetooth || transports[2].Available {
		t.Fatalf("transport status = %#v", transports)
	}

	params, err := json.Marshal(v1.GetRouteStatusRequest{ConnectionID: "not-active"})
	if err != nil {
		t.Fatal(err)
	}
	routeResponse := coreRequest(t, server, ipc.Request{
		Version: v1.Version,
		ID:      "network-2",
		Method:  v1.MethodRouteGet,
		Params:  params,
	})
	if routeResponse.Error == nil || routeResponse.Error.Code != ipc.ErrorRouteNotFound {
		t.Fatalf("route response = %#v", routeResponse)
	}
}

func coreRequest(t *testing.T, server *ipc.Server, request ipc.Request) ipc.Response {
	t.Helper()
	client, serverConn := net.Pipe()
	defer client.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ServeOne(context.Background(), serverConn) }()
	if err := ipc.WriteRequest(client, request); err != nil {
		t.Fatal(err)
	}
	response, err := ipc.ReadResponse(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	return response
}

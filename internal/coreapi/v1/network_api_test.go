package v1

import "testing"

func TestNetworkStatusMethodWireNames(t *testing.T) {
	if MethodTransportsList != "transports.list" {
		t.Fatalf("MethodTransportsList = %q", MethodTransportsList)
	}
	if MethodRouteGet != "route.get" {
		t.Fatalf("MethodRouteGet = %q", MethodRouteGet)
	}
}

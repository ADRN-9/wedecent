package main

import (
	"testing"

	"wedecent.com/wedecent/internal/mesh"
)

func TestBuildRoutedConnectRequestDisabledByDefault(t *testing.T) {
	request, enabled, err := buildRoutedConnectRequest(
		"wd_aaaaaaaaaaaaaaaa",
		"wd_cccccccccccccccc",
		routedConnectConfig{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("routing enabled without explicit route configuration")
	}
	if request.SourceDeviceID != "" || request.RouterDeviceID != "" {
		t.Fatalf("unexpected request: %+v", request)
	}
}

func TestBuildRoutedConnectRequestExactRoute(t *testing.T) {
	request, enabled, err := buildRoutedConnectRequest(
		"wd_aaaaaaaaaaaaaaaa",
		"wd_cccccccccccccccc",
		routedConnectConfig{
			RouterDeviceID:  "wd_bbbbbbbbbbbbbbbb",
			FirstTransport:  "lan",
			SecondTransport: "internet",
			FirstCost:       10,
			SecondCost:      20,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatal("explicit route configuration did not enable routing")
	}
	if request.SourceDeviceID != "wd_aaaaaaaaaaaaaaaa" ||
		request.RouterDeviceID != "wd_bbbbbbbbbbbbbbbb" ||
		request.DestinationDeviceID != "wd_cccccccccccccccc" ||
		request.FirstTransport != mesh.TransportLAN ||
		request.SecondTransport != mesh.TransportInternet ||
		request.FirstCost != 10 || request.SecondCost != 20 {
		t.Fatalf("unexpected request: %+v", request)
	}
}

func TestBuildRoutedConnectRequestRejectsPartialRoute(t *testing.T) {
	_, _, err := buildRoutedConnectRequest(
		"wd_aaaaaaaaaaaaaaaa",
		"wd_cccccccccccccccc",
		routedConnectConfig{
			RouterDeviceID: "wd_bbbbbbbbbbbbbbbb",
			FirstTransport: "lan",
		},
	)
	if err == nil {
		t.Fatal("partial routed connection configuration accepted")
	}
}

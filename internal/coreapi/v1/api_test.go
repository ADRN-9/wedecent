package v1

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestVersionAndWireValues(t *testing.T) {
	if Version != "v1" {
		t.Fatalf("Version = %q", Version)
	}

	paths := map[ConnectionPath]string{
		ConnectionPathDirect: "direct",
		ConnectionPathLAN:    "lan",
		ConnectionPathRouted: "routed",
		ConnectionPathRelay:  "relay",
	}
	for got, want := range paths {
		if string(got) != want {
			t.Fatalf("connection path = %q, want %q", got, want)
		}
	}

	transports := map[TransportName]string{
		TransportLAN:       "lan",
		TransportInternet:  "internet",
		TransportBluetooth: "bluetooth",
	}
	for got, want := range transports {
		if string(got) != want {
			t.Fatalf("transport = %q, want %q", got, want)
		}
	}
}

func TestStatusOmitsAbsentAccountIdentity(t *testing.T) {
	data, err := json.Marshal(Status{
		APIVersion: Version,
		DeviceID:   "wd_abcdefghijklmnop",
		DeviceName: "workstation",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "user_id") || strings.Contains(text, "email") {
		t.Fatalf("signed-out status leaked absent account fields: %s", text)
	}
}

func TestRouteStatusJSONRoundTrip(t *testing.T) {
	expires := time.Date(2026, 9, 20, 19, 0, 0, 0, time.UTC)
	want := RouteStatus{
		ConnectionID:  "conn-1",
		DestinationID: "wd_destination000",
		Path:          ConnectionPathRouted,
		RouterID:      "wd_router00000000",
		Hops: []RouteHop{
			{From: "wd_source00000000", To: "wd_router00000000", Transport: TransportLAN, Cost: 10},
			{From: "wd_router00000000", To: "wd_destination000", Transport: TransportInternet, Cost: 20},
		},
		ExpiresAt: &expires,
	}

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got RouteStatus
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

func TestPublicResponseTypesContainNoSecretFields(t *testing.T) {
	responseTypes := []reflect.Type{
		reflect.TypeOf(Status{}),
		reflect.TypeOf(Device{}),
		reflect.TypeOf(TransportStatus{}),
		reflect.TypeOf(Connection{}),
		reflect.TypeOf(RouteStatus{}),
		reflect.TypeOf(RouterPolicy{}),
		reflect.TypeOf(RouterStats{}),
	}
	forbidden := []string{"password", "private", "secret", "token", "grant"}

	for _, typ := range responseTypes {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			wireName := strings.Split(field.Tag.Get("json"), ",")[0]
			candidate := strings.ToLower(field.Name + " " + wireName)
			for _, word := range forbidden {
				if strings.Contains(candidate, word) {
					t.Fatalf("%s.%s exposes forbidden secret-bearing field %q", typ.Name(), field.Name, wireName)
				}
			}
		}
	}
}

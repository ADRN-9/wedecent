package desktopbridge

import (
	"context"
	"errors"
	"reflect"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type inventorySource struct {
	devices      []v1.Device
	transports   []v1.TransportStatus
	deviceErr    error
	transportErr error
}

func (s inventorySource) ListDevices(context.Context) ([]v1.Device, error) {
	return s.devices, s.deviceErr
}

func (s inventorySource) GetTransportStatus(context.Context) ([]v1.TransportStatus, error) {
	return s.transports, s.transportErr
}

func TestGetInventorySanitizesRendererState(t *testing.T) {
	source := inventorySource{
		devices: []v1.Device{{
			ID: "wd_0123456789abcdef", Name: "laptop",
			Fingerprint: "SHA256:must-not-leak", Endpoint: "tcp://192.0.2.10:8022",
		}},
		transports: []v1.TransportStatus{{
			Name: v1.TransportLAN, Available: true, Detail: "sensitive implementation detail",
		}},
	}

	got, err := GetInventory(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	want := Inventory{
		Devices:    []Device{{ID: "wd_0123456789abcdef", Name: "laptop"}},
		Transports: []Transport{{Name: v1.TransportLAN, Available: true}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetInventory() = %#v, want %#v", got, want)
	}
}

func TestGetInventoryRequiresSource(t *testing.T) {
	_, err := GetInventory(context.Background(), nil)
	if !errors.Is(err, ErrInventorySourceRequired) {
		t.Fatalf("GetInventory() error = %v, want %v", err, ErrInventorySourceRequired)
	}
}

func TestGetInventoryFailsClosedOnPartialCoreError(t *testing.T) {
	want := errors.New("transport status unavailable")
	_, err := GetInventory(context.Background(), inventorySource{
		devices:      []v1.Device{{ID: "wd_0123456789abcdef", Name: "laptop"}},
		transportErr: want,
	})
	if !errors.Is(err, want) {
		t.Fatalf("GetInventory() error = %v, want %v", err, want)
	}
}

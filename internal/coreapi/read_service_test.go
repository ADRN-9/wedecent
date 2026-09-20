package coreapi

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/account"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/trust"
)

func TestNewReadServiceValidatesDependencies(t *testing.T) {
	store, err := trust.Open(filepath.Join(t.TempDir(), "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	id := &identity.Identity{ID: "wd_aaaaaaaaaaaaaaaa", Name: "local"}

	if _, err := NewReadService(nil, nil, store); err == nil {
		t.Fatal("NewReadService(nil identity) succeeded")
	}
	if _, err := NewReadService(&identity.Identity{}, nil, store); err == nil {
		t.Fatal("NewReadService(empty identity) succeeded")
	}
	if _, err := NewReadService(id, nil, nil); err == nil {
		t.Fatal("NewReadService(nil store) succeeded")
	}
	if _, err := NewReadService(id, &account.Session{}, store); err == nil {
		t.Fatal("NewReadService(session without user ID) succeeded")
	}
}

func TestReadServiceStatusCopiesOnlyPublicSessionIdentity(t *testing.T) {
	store, err := trust.Open(filepath.Join(t.TempDir(), "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	id := &identity.Identity{ID: "wd_aaaaaaaaaaaaaaaa", Name: "local"}
	session := &account.Session{
		UserID:       " user-123 ",
		Email:        " person@example.test ",
		AccessToken:  "access-secret",
		RefreshToken: "refresh-secret",
	}
	service, err := NewReadService(id, session, store)
	if err != nil {
		t.Fatal(err)
	}

	session.UserID = "changed"
	session.Email = "changed@example.test"
	session.AccessToken = "changed-access-secret"

	status, err := service.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := v1.Status{
		APIVersion: v1.Version,
		SignedIn:   true,
		UserID:     "user-123",
		Email:      "person@example.test",
		DeviceID:   id.ID,
		DeviceName: id.Name,
	}
	if !reflect.DeepEqual(status, want) {
		t.Fatalf("status = %#v, want %#v", status, want)
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret") {
		t.Fatalf("status contains secret material: %s", data)
	}
}

func TestReadServiceSignedOutStatus(t *testing.T) {
	store, err := trust.Open(filepath.Join(t.TempDir(), "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewReadService(
		&identity.Identity{ID: "wd_aaaaaaaaaaaaaaaa", Name: "local"},
		nil,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}

	status, err := service.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.SignedIn || status.UserID != "" || status.Email != "" {
		t.Fatalf("signed-out status = %#v", status)
	}
}

func TestReadServiceListsDevicesDeterministically(t *testing.T) {
	store, err := trust.Open(filepath.Join(t.TempDir(), "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []trust.Peer{
		{ID: "wd_bbbbbbbbbbbbbbbb", Name: "beta", Fingerprint: "SHA256:BB", Endpoint: "relay://example/beta"},
		{ID: "wd_aaaaaaaaaaaaaaaa", Name: "alpha", Fingerprint: "SHA256:AA", Endpoint: "tcp://127.0.0.1:7443"},
	} {
		if err := store.Put(peer); err != nil {
			t.Fatal(err)
		}
	}
	service, err := NewReadService(
		&identity.Identity{ID: "wd_local0000000000", Name: "local"},
		nil,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}

	devices, err := service.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d", len(devices))
	}
	if devices[0].ID != "wd_aaaaaaaaaaaaaaaa" || devices[1].ID != "wd_bbbbbbbbbbbbbbbb" {
		t.Fatalf("device order = %#v", devices)
	}
	if devices[0].Endpoint != "tcp://127.0.0.1:7443" || devices[0].Fingerprint != "SHA256:AA" {
		t.Fatalf("device mapping = %#v", devices[0])
	}
}

func TestReadServiceGetDevice(t *testing.T) {
	store, err := trust.Open(filepath.Join(t.TempDir(), "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	peer := trust.Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "alpha", Fingerprint: "SHA256:AA"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
	service, err := NewReadService(
		&identity.Identity{ID: "wd_local0000000000", Name: "local"},
		nil,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}

	device, err := service.GetDevice(context.Background(), v1.GetDeviceRequest{DeviceID: "  " + peer.ID + "  "})
	if err != nil {
		t.Fatal(err)
	}
	if device.ID != peer.ID || device.Name != peer.Name || device.Fingerprint != peer.Fingerprint {
		t.Fatalf("device = %#v", device)
	}

	_, err = service.GetDevice(context.Background(), v1.GetDeviceRequest{DeviceID: "wd_missing00000000"})
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("missing device error = %v", err)
	}
}

func TestReadServiceHonorsCanceledContext(t *testing.T) {
	store, err := trust.Open(filepath.Join(t.TempDir(), "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewReadService(
		&identity.Identity{ID: "wd_aaaaaaaaaaaaaaaa", Name: "local"},
		nil,
		store,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := service.GetStatus(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetStatus canceled error = %v", err)
	}
	if _, err := service.ListDevices(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListDevices canceled error = %v", err)
	}
	if _, err := service.GetDevice(ctx, v1.GetDeviceRequest{DeviceID: "wd_aaaaaaaaaaaaaaaa"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetDevice canceled error = %v", err)
	}
}

func TestReadServiceDoesNotRetainCredentialContainers(t *testing.T) {
	typ := reflect.TypeOf(ReadService{})
	accountSession := reflect.TypeOf((*account.Session)(nil))
	deviceIdentity := reflect.TypeOf((*identity.Identity)(nil))
	forbiddenNames := []string{"password", "private", "secret", "token", "grant"}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Type == accountSession || field.Type == deviceIdentity {
			t.Fatalf("ReadService retains credential container %s", field.Type)
		}
		name := strings.ToLower(field.Name)
		for _, forbidden := range forbiddenNames {
			if strings.Contains(name, forbidden) {
				t.Fatalf("ReadService field %q may retain secret material", field.Name)
			}
		}
	}
}

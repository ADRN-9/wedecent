package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeCoreSource struct {
	status       v1.Status
	statusErr    error
	devices      []v1.Device
	devicesErr   error
	transports   []v1.TransportStatus
	transportErr error
}

func (f fakeCoreSource) GetStatus(context.Context) (v1.Status, error) {
	return f.status, f.statusErr
}

func (f fakeCoreSource) ListDevices(context.Context) ([]v1.Device, error) {
	return f.devices, f.devicesErr
}

func (f fakeCoreSource) GetTransportStatus(context.Context) ([]v1.TransportStatus, error) {
	return f.transports, f.transportErr
}

func TestRunStatusEmitsSanitizedJSON(t *testing.T) {
	source := fakeCoreSource{status: v1.Status{
		APIVersion: "v1",
		SignedIn:   true,
		UserID:     "user-123",
		Email:      "person@example.com",
		DeviceID:   "wd_0123456789abcdef",
		DeviceName: "laptop",
	}}
	var out bytes.Buffer
	if err := run([]string{"status"}, &out, source); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{`"api_version":"v1"`, `"signed_in":true`, `"device_id":"wd_0123456789abcdef"`, `"device_name":"laptop"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("status output %q does not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"user-123", "person@example.com", "fingerprint", "endpoint"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("status output %q contains forbidden renderer data %q", got, forbidden)
		}
	}
}

func TestRunInventoryEmitsSanitizedJSON(t *testing.T) {
	source := fakeCoreSource{
		devices: []v1.Device{{ID: "wd_0123456789abcdef", Name: "laptop", Fingerprint: "SHA256:secretish", Endpoint: "tcp://192.0.2.5:8022"}},
		transports: []v1.TransportStatus{{Name: v1.TransportLAN, Available: true, Detail: "implementation detail"}},
	}
	var out bytes.Buffer
	if err := run([]string{"inventory"}, &out, source); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{`"id":"wd_0123456789abcdef"`, `"name":"laptop"`, `"name":"lan"`, `"available":true`} {
		if !strings.Contains(got, want) {
			t.Fatalf("inventory output %q does not contain %q", got, want)
		}
	}
	for _, forbidden := range []string{"SHA256:secretish", "192.0.2.5", "implementation detail", "fingerprint", "endpoint", "detail"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("inventory output %q contains forbidden renderer data %q", got, forbidden)
		}
	}
}

func TestRunDoesNotEmitPartialJSONOnCoreError(t *testing.T) {
	want := errors.New("boom")
	var out bytes.Buffer
	err := run([]string{"status"}, &out, fakeCoreSource{statusErr: want})
	if !errors.Is(err, want) {
		t.Fatalf("run() error = %v, want %v", err, want)
	}
	if out.Len() != 0 {
		t.Fatalf("status output = %q, want empty", out.String())
	}
}

func TestRunRejectsUnknownCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"status", "extra"}} {
		if err := run(args, &bytes.Buffer{}, fakeCoreSource{}); !errors.Is(err, errUsage) {
			t.Fatalf("run(%q) error = %v, want usage", args, err)
		}
	}
}

func TestPublicErrorDoesNotLeakRemoteMessage(t *testing.T) {
	remote := &coreclient.RemoteError{Code: "denied", Message: "sensitive implementation detail"}
	got := publicError(remote)
	if strings.Contains(got, remote.Message) || strings.Contains(got, remote.Code) {
		t.Fatalf("publicError() leaked remote detail: %q", got)
	}
	if got != "Local Core rejected the desktop request" {
		t.Fatalf("publicError() = %q", got)
	}
}

func TestPublicErrorClassifiesUnavailable(t *testing.T) {
	if got := publicError(coreclient.ErrUnavailable); got != "Local Core is unavailable" {
		t.Fatalf("publicError() = %q", got)
	}
}

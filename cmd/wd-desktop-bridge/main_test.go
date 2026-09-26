package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	connection   v1.Connection
	read         v1.TerminalReadResult
	writeReq     v1.TerminalWriteRequest
	resizeReq    v1.TerminalResizeRequest
	disconnect   v1.DisconnectRequest
}

func (f *fakeCoreSource) GetStatus(context.Context) (v1.Status, error) { return f.status, f.statusErr }
func (f *fakeCoreSource) ListDevices(context.Context) ([]v1.Device, error) { return f.devices, f.devicesErr }
func (f *fakeCoreSource) GetTransportStatus(context.Context) ([]v1.TransportStatus, error) { return f.transports, f.transportErr }
func (f *fakeCoreSource) Connect(context.Context, v1.ConnectRequest) (v1.Connection, error) { return f.connection, nil }
func (f *fakeCoreSource) Disconnect(_ context.Context, req v1.DisconnectRequest) error { f.disconnect = req; return nil }
func (f *fakeCoreSource) ReadTerminal(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error) { return f.read, nil }
func (f *fakeCoreSource) WriteTerminal(_ context.Context, req v1.TerminalWriteRequest) error { f.writeReq = req; return nil }
func (f *fakeCoreSource) ResizeTerminal(_ context.Context, req v1.TerminalResizeRequest) error { f.resizeReq = req; return nil }

func TestRunStatusEmitsSanitizedJSON(t *testing.T) {
	source := &fakeCoreSource{status: v1.Status{APIVersion: "v1", SignedIn: true, UserID: "user-123", Email: "person@example.com", DeviceID: "wd_0123456789abcdef", DeviceName: "laptop"}}
	var out bytes.Buffer
	if err := run([]string{"status"}, strings.NewReader(""), &out, source); err != nil { t.Fatal(err) }
	got := out.String()
	for _, want := range []string{`"api_version":"v1"`, `"signed_in":true`, `"device_id":"wd_0123456789abcdef"`, `"device_name":"laptop"`} {
		if !strings.Contains(got, want) { t.Fatalf("status output %q does not contain %q", got, want) }
	}
	for _, forbidden := range []string{"user-123", "person@example.com", "fingerprint", "endpoint"} {
		if strings.Contains(got, forbidden) { t.Fatalf("status output %q contains forbidden renderer data %q", got, forbidden) }
	}
}

func TestRunInventoryEmitsSanitizedJSON(t *testing.T) {
	source := &fakeCoreSource{devices: []v1.Device{{ID: "wd_0123456789abcdef", Name: "laptop", Fingerprint: "SHA256:secretish", Endpoint: "tcp://192.0.2.5:8022"}}, transports: []v1.TransportStatus{{Name: v1.TransportLAN, Available: true, Detail: "implementation detail"}}}
	var out bytes.Buffer
	if err := run([]string{"inventory"}, strings.NewReader(""), &out, source); err != nil { t.Fatal(err) }
	got := out.String()
	for _, forbidden := range []string{"SHA256:secretish", "192.0.2.5", "implementation detail", "fingerprint", "endpoint", "detail"} {
		if strings.Contains(got, forbidden) { t.Fatalf("inventory output %q contains forbidden renderer data %q", got, forbidden) }
	}
}

func TestRunTerminalCommandsUseJSONStdin(t *testing.T) {
	source := &fakeCoreSource{connection: v1.Connection{ID: "conn_abc", DeviceID: "wd_0123456789abcdef", State: v1.ConnectionStateConnected, Path: v1.ConnectionPathDirect}, read: v1.TerminalReadResult{Data: []byte("hello")}}
	var out bytes.Buffer
	if err := run([]string{"connect"}, strings.NewReader(`{"id":"wd_0123456789abcdef"}`), &out, source); err != nil { t.Fatal(err) }
	if !strings.Contains(out.String(), `"id":"conn_abc"`) { t.Fatalf("connect output = %q", out.String()) }

	out.Reset()
	if err := run([]string{"terminal-read"}, strings.NewReader(`{"id":"conn_abc"}`), &out, source); err != nil { t.Fatal(err) }
	if !strings.Contains(out.String(), base64.StdEncoding.EncodeToString([]byte("hello"))) { t.Fatalf("read output = %q", out.String()) }

	out.Reset()
	if err := run([]string{"terminal-write"}, strings.NewReader(`{"id":"conn_abc","data":"aGk="}`), &out, source); err != nil { t.Fatal(err) }
	if string(source.writeReq.Data) != "hi" || !strings.Contains(out.String(), `"ok":true`) { t.Fatalf("write = %#v output=%q", source.writeReq, out.String()) }

	out.Reset()
	if err := run([]string{"terminal-resize"}, strings.NewReader(`{"id":"conn_abc","cols":120,"rows":40}`), &out, source); err != nil { t.Fatal(err) }
	if source.resizeReq.Cols != 120 || source.resizeReq.Rows != 40 { t.Fatalf("resize = %#v", source.resizeReq) }
}

func TestRunRejectsMalformedTerminalRequests(t *testing.T) {
	source := &fakeCoreSource{}
	for _, input := range []string{`{"id":"conn_abc","extra":true}`, `{"id":"conn_abc"} {"id":"conn_2"}`, `not-json`} {
		if err := run([]string{"terminal-read"}, strings.NewReader(input), &bytes.Buffer{}, source); err == nil { t.Fatalf("accepted %q", input) }
	}
}

func TestRunDoesNotEmitPartialJSONOnCoreError(t *testing.T) {
	want := errors.New("boom")
	source := &fakeCoreSource{statusErr: want}
	var out bytes.Buffer
	err := run([]string{"status"}, strings.NewReader(""), &out, source)
	if !errors.Is(err, want) || out.Len() != 0 { t.Fatalf("error=%v output=%q", err, out.String()) }
}

func TestRunRejectsUnknownCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"status", "extra"}} {
		if err := run(args, strings.NewReader(""), &bytes.Buffer{}, &fakeCoreSource{}); !errors.Is(err, errUsage) { t.Fatalf("run(%q) error = %v", args, err) }
	}
}

func TestPublicErrorDoesNotLeakRemoteMessage(t *testing.T) {
	remote := &coreclient.RemoteError{Code: "denied", Message: "sensitive implementation detail"}
	got := publicError(remote)
	if strings.Contains(got, remote.Message) || strings.Contains(got, remote.Code) { t.Fatalf("publicError() leaked remote detail: %q", got) }
	if got != "Local Core rejected the desktop request" { t.Fatalf("publicError() = %q", got) }
}

func TestPublicErrorClassifiesUnavailable(t *testing.T) {
	if got := publicError(coreclient.ErrUnavailable); got != "Local Core is unavailable" { t.Fatalf("publicError() = %q", got) }
}

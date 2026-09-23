package guiapp

import (
	"context"
	"errors"
	"sync"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeCore struct {
	mu sync.Mutex

	status        v1.Status
	devices       []v1.Device
	connection    v1.Connection
	connectErr    error
	disconnectErr error
	readResult    v1.TerminalReadResult
	readErr       error
	writeErr      error
	resizeErr     error

	connectStarted chan struct{}
	connectRelease chan struct{}

	lastConnectID    string
	lastDisconnectID string
	lastReadID       string
	lastWriteID      string
	lastWriteData    []byte
	lastResizeID     string
	lastCols         uint16
	lastRows         uint16
}

func (f *fakeCore) GetStatus(context.Context) (v1.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, nil
}

func (f *fakeCore) ListDevices(context.Context) ([]v1.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]v1.Device(nil), f.devices...), nil
}

func (f *fakeCore) GetDevice(context.Context, v1.GetDeviceRequest) (v1.Device, error) {
	return v1.Device{}, errors.New("unused")
}

func (f *fakeCore) Connect(ctx context.Context, req v1.ConnectRequest) (v1.Connection, error) {
	f.mu.Lock()
	f.lastConnectID = req.DeviceID
	started := f.connectStarted
	release := f.connectRelease
	connection := f.connection
	err := f.connectErr
	f.mu.Unlock()
	if started != nil {
		select {
		case <-started:
		default:
			close(started)
		}
	}
	if release != nil {
		select {
		case <-ctx.Done():
			return v1.Connection{}, ctx.Err()
		case <-release:
		}
	}
	return connection, err
}

func (f *fakeCore) Disconnect(_ context.Context, req v1.DisconnectRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastDisconnectID = req.ConnectionID
	return f.disconnectErr
}

func (f *fakeCore) ReadTerminal(_ context.Context, req v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReadID = req.ConnectionID
	return f.readResult, f.readErr
}

func (f *fakeCore) WriteTerminal(_ context.Context, req v1.TerminalWriteRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastWriteID = req.ConnectionID
	f.lastWriteData = append([]byte(nil), req.Data...)
	for i := range req.Data {
		req.Data[i] = 0
	}
	return f.writeErr
}

func (f *fakeCore) ResizeTerminal(_ context.Context, req v1.TerminalResizeRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastResizeID = req.ConnectionID
	f.lastCols, f.lastRows = req.Cols, req.Rows
	return f.resizeErr
}

func TestControllerRefreshCopiesAndMinimizesDevices(t *testing.T) {
	core := &fakeCore{
		status: v1.Status{APIVersion: v1.Version, DeviceID: "wd_local000000000"},
		devices: []v1.Device{{
			ID:          "wd_peer0000000000",
			Name:        "peer",
			Fingerprint: "AA:BB",
			Endpoint:    "wsrelay://private.example.test/path",
		}},
	}
	controller, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := controller.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status.DeviceID != core.status.DeviceID || len(snapshot.Devices) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if snapshot.Devices[0].ID != core.devices[0].ID || snapshot.Devices[0].Name != core.devices[0].Name {
		t.Fatalf("device = %#v", snapshot.Devices[0])
	}
	if snapshot.Devices[0].Fingerprint != "" || snapshot.Devices[0].Endpoint != "" {
		t.Fatalf("GUI retained networking identity detail: %#v", snapshot.Devices[0])
	}
	snapshot.Devices[0].Name = "changed"
	if core.devices[0].Name != "peer" {
		t.Fatal("refresh exposed mutable core device storage")
	}
}

func TestControllerPreventsConcurrentConnects(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	core := &fakeCore{
		connection:     v1.Connection{ID: "conn_1", DeviceID: "wd_peer0000000000", State: v1.ConnectionStateConnected},
		connectStarted: started,
		connectRelease: release,
	}
	controller, err := New(core)
	if err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := controller.Connect(context.Background(), "wd_peer0000000000")
		firstDone <- err
	}()
	<-started
	if _, err := controller.Connect(context.Background(), "wd_other000000000"); !errors.Is(err, ErrSessionActive) {
		t.Fatalf("second connect error = %v", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestControllerTerminalLifecycleUsesOpaqueConnectionID(t *testing.T) {
	core := &fakeCore{
		connection: v1.Connection{ID: "conn_opaque", DeviceID: "wd_peer0000000000", State: v1.ConnectionStateConnected},
		readResult: v1.TerminalReadResult{Data: []byte("done"), Closed: true},
	}
	controller, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Connect(context.Background(), "wd_peer0000000000"); err != nil {
		t.Fatal(err)
	}

	input := []byte("echo test\n")
	if err := controller.WriteTerminal(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if string(input) != "echo test\n" {
		t.Fatalf("caller input mutated: %q", input)
	}
	if err := controller.ResizeTerminal(context.Background(), 120, 40); err != nil {
		t.Fatal(err)
	}
	result, err := controller.ReadTerminal(context.Background(), v1.MaxTerminalChunkBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Data) != "done" || !result.Closed {
		t.Fatalf("read result = %#v", result)
	}
	if _, ok := controller.ActiveConnection(); ok {
		t.Fatal("closed terminal left GUI session active")
	}

	core.mu.Lock()
	defer core.mu.Unlock()
	if core.lastWriteID != "conn_opaque" || core.lastReadID != "conn_opaque" || core.lastResizeID != "conn_opaque" {
		t.Fatalf("terminal ids: write=%q read=%q resize=%q", core.lastWriteID, core.lastReadID, core.lastResizeID)
	}
	if core.lastCols != 120 || core.lastRows != 40 {
		t.Fatalf("resize = %dx%d", core.lastCols, core.lastRows)
	}
}

func TestControllerDisconnectFailureKeepsRetryableSession(t *testing.T) {
	core := &fakeCore{
		connection:    v1.Connection{ID: "conn_retry", DeviceID: "wd_peer0000000000", State: v1.ConnectionStateConnected},
		disconnectErr: errors.New("close failed"),
	}
	controller, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Connect(context.Background(), "wd_peer0000000000"); err != nil {
		t.Fatal(err)
	}
	if err := controller.Disconnect(context.Background()); err == nil {
		t.Fatal("disconnect unexpectedly succeeded")
	}
	connection, ok := controller.ActiveConnection()
	if !ok || connection.ID != "conn_retry" {
		t.Fatalf("active after failed disconnect = %#v, %v", connection, ok)
	}
}

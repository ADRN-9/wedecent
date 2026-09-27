package coreapi

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeLatencyConnectionHandle struct {
	fakeConnectionHandle
	rtt   time.Duration
	err   error
	calls int
}

func (h *fakeLatencyConnectionHandle) ProbeLatency(ctx context.Context) (time.Duration, error) {
	h.calls++
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return h.rtt, h.err
}

func TestConnectionServiceProbeConnectionLatency(t *testing.T) {
	handle := &fakeLatencyConnectionHandle{rtt: 12*time.Millisecond + 345*time.Microsecond}
	backend := &fakeConnectionBackend{opened: OpenedConnection{
		Path:   v1.ConnectionPathRelay,
		Handle: handle,
	}}
	now := time.Date(2026, 9, 26, 23, 55, 0, 0, time.UTC)
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x61}, 18)),
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}

	got, err := service.ProbeConnectionLatency(context.Background(), v1.ConnectionLatencyRequest{ConnectionID: connection.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got.ConnectionID != connection.ID || got.RTTMicros != 12345 || !got.MeasuredAt.Equal(now) {
		t.Fatalf("latency = %#v", got)
	}
	if handle.calls != 1 {
		t.Fatalf("probe calls = %d, want 1", handle.calls)
	}
}

func TestConnectionServiceProbeConnectionLatencyFailsClosed(t *testing.T) {
	unsupported := &fakeConnectionHandle{}
	backend := &fakeConnectionBackend{opened: OpenedConnection{
		Path:   v1.ConnectionPathDirect,
		Handle: unsupported,
	}}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x62}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.ProbeConnectionLatency(context.Background(), v1.ConnectionLatencyRequest{ConnectionID: " bad "}); !errors.Is(err, ErrInvalidConnectionRequest) {
		t.Fatalf("invalid ID error = %v", err)
	}
	if _, err := service.ProbeConnectionLatency(context.Background(), v1.ConnectionLatencyRequest{ConnectionID: "conn_missing"}); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("missing connection error = %v", err)
	}
	if _, err := service.ProbeConnectionLatency(context.Background(), v1.ConnectionLatencyRequest{ConnectionID: connection.ID}); !errors.Is(err, ErrConnectionLatencyUnavailable) {
		t.Fatalf("unsupported handle error = %v", err)
	}
}

func TestConnectionServiceProbeConnectionLatencyPreservesCancellationAndSanitizesBackendFailure(t *testing.T) {
	handle := &fakeLatencyConnectionHandle{err: errors.New("sensitive transport detail")}
	backend := &fakeConnectionBackend{opened: OpenedConnection{
		Path:   v1.ConnectionPathRelay,
		Handle: handle,
	}}
	service, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x63}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.ProbeConnectionLatency(context.Background(), v1.ConnectionLatencyRequest{ConnectionID: connection.ID})
	if !errors.Is(err, ErrConnectionLatencyOperation) || err.Error() != ErrConnectionLatencyOperation.Error() {
		t.Fatalf("backend probe error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.ProbeConnectionLatency(ctx, v1.ConnectionLatencyRequest{ConnectionID: connection.ID}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe error = %v", err)
	}
}

func TestConnectIdempotencyServiceDelegatesConnectionLatency(t *testing.T) {
	handle := &fakeLatencyConnectionHandle{rtt: time.Millisecond}
	backend := &fakeConnectionBackend{opened: OpenedConnection{Path: v1.ConnectionPathLAN, Handle: handle}}
	inner, err := NewConnectionService(ConnectionServiceConfig{
		Backend: backend,
		Network: newConnectionTestNetwork(t),
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x64}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := NewConnectIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := wrapped.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.ProbeConnectionLatency(context.Background(), v1.ConnectionLatencyRequest{ConnectionID: connection.ID}); err != nil {
		t.Fatal(err)
	}
}

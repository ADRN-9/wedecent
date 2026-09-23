package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeUICore struct {
	getStatus      func(context.Context) (v1.Status, error)
	listDevices    func(context.Context) ([]v1.Device, error)
	getDevice      func(context.Context, v1.GetDeviceRequest) (v1.Device, error)
	connect        func(context.Context, v1.ConnectRequest) (v1.Connection, error)
	disconnect     func(context.Context, v1.DisconnectRequest) error
	readTerminal   func(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error)
	writeTerminal  func(context.Context, v1.TerminalWriteRequest) error
	resizeTerminal func(context.Context, v1.TerminalResizeRequest) error
}

func (f *fakeUICore) GetStatus(ctx context.Context) (v1.Status, error) {
	if f.getStatus != nil {
		return f.getStatus(ctx)
	}
	return v1.Status{}, nil
}

func (f *fakeUICore) ListDevices(ctx context.Context) ([]v1.Device, error) {
	if f.listDevices != nil {
		return f.listDevices(ctx)
	}
	return nil, nil
}

func (f *fakeUICore) GetDevice(ctx context.Context, req v1.GetDeviceRequest) (v1.Device, error) {
	if f.getDevice != nil {
		return f.getDevice(ctx, req)
	}
	return v1.Device{}, nil
}

func (f *fakeUICore) Connect(ctx context.Context, req v1.ConnectRequest) (v1.Connection, error) {
	if f.connect != nil {
		return f.connect(ctx, req)
	}
	return v1.Connection{}, nil
}

func (f *fakeUICore) Disconnect(ctx context.Context, req v1.DisconnectRequest) error {
	if f.disconnect != nil {
		return f.disconnect(ctx, req)
	}
	return nil
}

func (f *fakeUICore) ReadTerminal(ctx context.Context, req v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	if f.readTerminal != nil {
		return f.readTerminal(ctx, req)
	}
	return v1.TerminalReadResult{}, nil
}

func (f *fakeUICore) WriteTerminal(ctx context.Context, req v1.TerminalWriteRequest) error {
	if f.writeTerminal != nil {
		return f.writeTerminal(ctx, req)
	}
	return nil
}

func (f *fakeUICore) ResizeTerminal(ctx context.Context, req v1.TerminalResizeRequest) error {
	if f.resizeTerminal != nil {
		return f.resizeTerminal(ctx, req)
	}
	return nil
}

func unavailableForTest() error {
	return fmt.Errorf("%w: test transport", coreclient.ErrUnavailable)
}

func TestRecoveringCoreRetriesSafeStatusAfterRecovery(t *testing.T) {
	var calls int
	inner := &fakeUICore{getStatus: func(context.Context) (v1.Status, error) {
		calls++
		if calls == 1 {
			return v1.Status{}, unavailableForTest()
		}
		return v1.Status{DeviceID: "device-a"}, nil
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	status, err := core.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}
	if status.DeviceID != "device-a" {
		t.Fatalf("GetStatus() DeviceID = %q", status.DeviceID)
	}
	if calls != 2 || recoverCalls != 1 {
		t.Fatalf("status calls = %d, recovery calls = %d; want 2, 1", calls, recoverCalls)
	}
}

func TestRecoveringCoreReplaysIdempotentConnect(t *testing.T) {
	var connectCalls int
	var operationID string
	inner := &fakeUICore{connect: func(_ context.Context, req v1.ConnectRequest) (v1.Connection, error) {
		connectCalls++
		if req.OperationID == "" {
			t.Fatal("Connect request did not include an operation ID")
		}
		if operationID == "" {
			operationID = req.OperationID
		} else if req.OperationID != operationID {
			t.Fatalf("operation ID changed across retry: %q != %q", req.OperationID, operationID)
		}
		return v1.Connection{}, unavailableForTest()
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	_, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if !errors.Is(err, ErrConnectOutcomeUnknown) || !errors.Is(err, coreclient.ErrUnavailable) {
		t.Fatalf("Connect() error = %v; want unknown outcome wrapping ErrUnavailable", err)
	}
	if connectCalls != 2 || recoverCalls != 1 {
		t.Fatalf("connect calls = %d, recovery calls = %d; want 2, 1", connectCalls, recoverCalls)
	}
}

func TestRecoveringCoreDoesNotReplayTerminalWrite(t *testing.T) {
	var writeCalls int
	inner := &fakeUICore{writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
		writeCalls++
		return unavailableForTest()
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	err := core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "c", Data: []byte("x")})
	if !errors.Is(err, coreclient.ErrUnavailable) {
		t.Fatalf("WriteTerminal() error = %v; want ErrUnavailable", err)
	}
	if writeCalls != 1 || recoverCalls != 1 {
		t.Fatalf("write calls = %d, recovery calls = %d; want 1, 1", writeCalls, recoverCalls)
	}
}

func TestRecoveringCoreReadLeavesRetryToController(t *testing.T) {
	var readCalls int
	inner := &fakeUICore{readTerminal: func(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
		readCalls++
		return v1.TerminalReadResult{}, unavailableForTest()
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	_, err := core.ReadTerminal(context.Background(), v1.TerminalReadRequest{ConnectionID: "c"})
	if !errors.Is(err, coreclient.ErrUnavailable) {
		t.Fatalf("ReadTerminal() error = %v; want ErrUnavailable", err)
	}
	if readCalls != 1 || recoverCalls != 1 {
		t.Fatalf("read calls = %d, recovery calls = %d; want 1, 1", readCalls, recoverCalls)
	}
}

func TestRecoveringCoreDoesNotRecoverRemoteProtocolError(t *testing.T) {
	inner := &fakeUICore{getStatus: func(context.Context) (v1.Status, error) {
		return v1.Status{}, &coreclient.RemoteError{Code: ipc.ErrorConnectionUnavailable, Message: "temporarily unavailable"}
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	_, err := core.GetStatus(context.Background())
	if !coreclient.IsRemoteCode(err, ipc.ErrorConnectionUnavailable) {
		t.Fatalf("GetStatus() error = %v; want remote connection_unavailable", err)
	}
	if recoverCalls != 0 {
		t.Fatalf("recovery calls = %d; want 0", recoverCalls)
	}
}

func TestRecoveringCoreCoalescesConcurrentRecovery(t *testing.T) {
	var healthy atomic.Bool
	probeSeen := make(chan struct{}, 2)
	inner := &fakeUICore{getStatus: func(context.Context) (v1.Status, error) {
		if healthy.Load() {
			return v1.Status{DeviceID: "ready"}, nil
		}
		probeSeen <- struct{}{}
		return v1.Status{}, unavailableForTest()
	}}

	started := make(chan struct{})
	release := make(chan struct{})
	var recoverCalls atomic.Int32
	core := newRecoveringCore(inner, func(context.Context) error {
		if recoverCalls.Add(1) == 1 {
			close(started)
		}
		<-release
		healthy.Store(true)
		return nil
	})

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := core.GetStatus(context.Background())
			errs <- err
		}()
	}

	<-started
	<-probeSeen
	<-probeSeen
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent GetStatus() error = %v", err)
		}
	}
	if got := recoverCalls.Load(); got != 1 {
		t.Fatalf("recovery calls = %d; want 1", got)
	}
}

func TestRecoveringCoreReturnsRecoveryFailureForSafeReplay(t *testing.T) {
	inner := &fakeUICore{getStatus: func(context.Context) (v1.Status, error) {
		return v1.Status{}, unavailableForTest()
	}}
	recoveryErr := errors.New("stable recovery failure")
	core := newRecoveringCore(inner, func(context.Context) error { return recoveryErr })

	_, err := core.GetStatus(context.Background())
	if !errors.Is(err, recoveryErr) {
		t.Fatalf("GetStatus() error = %v; want recovery failure", err)
	}
}

func TestRecoveringCoreRetriesIdempotentDisconnect(t *testing.T) {
	var calls int
	inner := &fakeUICore{disconnect: func(context.Context, v1.DisconnectRequest) error {
		calls++
		if calls == 1 {
			return unavailableForTest()
		}
		return nil
	}}
	core := newRecoveringCore(inner, func(context.Context) error { return nil })

	if err := core.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: "c"}); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("disconnect calls = %d; want 2", calls)
	}
}

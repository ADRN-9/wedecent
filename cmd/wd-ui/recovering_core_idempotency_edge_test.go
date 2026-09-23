package main

import (
	"context"
	"errors"
	"testing"
	"time"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestRecoveringCoreKeepsFirstAmbiguousConnectKeyAfterPreWriteRetryFailure(t *testing.T) {
	var calls int
	var operationID string
	inner := &fakeUICore{connect: func(_ context.Context, req v1.ConnectRequest) (v1.Connection, error) {
		calls++
		if operationID == "" {
			operationID = req.OperationID
		} else if req.OperationID != operationID {
			t.Fatalf("operation ID changed across reconciliation: %q != %q", req.OperationID, operationID)
		}
		switch calls {
		case 1:
			return v1.Connection{}, unavailableStage(coreclient.UnavailableStageReadResponse)
		case 2:
			return v1.Connection{}, unavailableStage(coreclient.UnavailableStageDial)
		default:
			return v1.Connection{ID: "conn_reconciled", DeviceID: req.DeviceID}, nil
		}
	}}
	core := newRecoveringCore(inner, func(context.Context) error { return nil })

	_, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if !errors.Is(err, ErrConnectOutcomeUnknown) {
		t.Fatalf("first Connect() error = %v; want ErrConnectOutcomeUnknown", err)
	}
	connection, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if err != nil {
		t.Fatalf("reconciliation Connect() error = %v", err)
	}
	if connection.ID != "conn_reconciled" {
		t.Fatalf("connection = %#v", connection)
	}
	if calls != 3 {
		t.Fatalf("Connect calls = %d; want 3", calls)
	}
}

func TestRecoveringCoreExpiredPendingConnectFailsClosed(t *testing.T) {
	var calls int
	recoveryErr := errors.New("recovery failed")
	inner := &fakeUICore{connect: func(context.Context, v1.ConnectRequest) (v1.Connection, error) {
		calls++
		return v1.Connection{}, unavailableStage(coreclient.UnavailableStageReadResponse)
	}}
	wrapped := newRecoveringCore(inner, func(context.Context) error { return recoveryErr })
	core := wrapped.(*recoveringCore)

	_, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if !errors.Is(err, ErrConnectOutcomeUnknown) {
		t.Fatalf("first Connect() error = %v; want ErrConnectOutcomeUnknown", err)
	}

	core.mu.Lock()
	core.pendingConnectExpiresAt = time.Now().Add(-time.Second)
	core.mu.Unlock()

	_, err = core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if !errors.Is(err, ErrConnectOutcomeUnknown) {
		t.Fatalf("expired Connect() error = %v; want ErrConnectOutcomeUnknown", err)
	}
	if calls != 1 {
		t.Fatalf("inner Connect calls = %d; want 1 because expired replay key must not be reused", calls)
	}
}

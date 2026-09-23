package main

import (
	"context"
	"errors"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestRecoveringCoreConnectTimeoutAfterWriteReconciles(t *testing.T) {
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
		if connectCalls == 1 {
			return v1.Connection{}, errors.Join(
				context.DeadlineExceeded,
				&coreclient.UnavailableError{Stage: coreclient.UnavailableStageReadResponse},
			)
		}
		return v1.Connection{ID: "conn_reconciled", DeviceID: req.DeviceID}, nil
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	connection, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if connection.ID != "conn_reconciled" {
		t.Fatalf("Connect() result = %#v", connection)
	}
	if connectCalls != 2 || recoverCalls != 1 {
		t.Fatalf("connect calls = %d, recovery calls = %d; want 2, 1", connectCalls, recoverCalls)
	}
}

func TestRecoveringCoreTerminalWriteCanceledAfterWriteIsOutcomeUnknown(t *testing.T) {
	var writeCalls int
	inner := &fakeUICore{writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
		writeCalls++
		return errors.Join(
			context.Canceled,
			&coreclient.UnavailableError{Stage: coreclient.UnavailableStageWriteRequest},
		)
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	err := core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "c", Data: []byte("x")})
	if !errors.Is(err, ErrTerminalWriteOutcomeUnknown) {
		t.Fatalf("WriteTerminal() error = %v; want ErrTerminalWriteOutcomeUnknown", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WriteTerminal() error = %v; want cancellation cause preserved", err)
	}
	if writeCalls != 1 || recoverCalls != 1 {
		t.Fatalf("write calls = %d, recovery calls = %d; want 1, 1", writeCalls, recoverCalls)
	}
}

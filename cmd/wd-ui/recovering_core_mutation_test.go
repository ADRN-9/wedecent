package main

import (
	"context"
	"errors"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func unavailableStage(stage coreclient.UnavailableStage) error {
	return &coreclient.UnavailableError{Stage: stage}
}

func TestRecoveringCoreRetriesConnectBeforeRequestWrite(t *testing.T) {
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
			return v1.Connection{}, unavailableStage(coreclient.UnavailableStageDial)
		}
		return v1.Connection{ID: "conn_ready"}, nil
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
	if connection.ID != "conn_ready" {
		t.Fatalf("Connect() ID = %q, want conn_ready", connection.ID)
	}
	if connectCalls != 2 || recoverCalls != 1 {
		t.Fatalf("connect calls = %d, recovery calls = %d; want 2, 1", connectCalls, recoverCalls)
	}
}

func TestRecoveringCoreRetriesConnectAfterResponseLoss(t *testing.T) {
	var connectCalls int
	var operationID string
	inner := &fakeUICore{connect: func(_ context.Context, req v1.ConnectRequest) (v1.Connection, error) {
		connectCalls++
		if operationID == "" {
			operationID = req.OperationID
		} else if req.OperationID != operationID {
			t.Fatalf("operation ID changed across ambiguous retry: %q != %q", req.OperationID, operationID)
		}
		if connectCalls == 1 {
			return v1.Connection{}, unavailableStage(coreclient.UnavailableStageReadResponse)
		}
		return v1.Connection{ID: "conn_reconciled"}, nil
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
		t.Fatalf("Connect() ID = %q, want conn_reconciled", connection.ID)
	}
	if connectCalls != 2 || recoverCalls != 1 {
		t.Fatalf("connect calls = %d, recovery calls = %d; want 2, 1", connectCalls, recoverCalls)
	}
}

func TestRecoveringCoreReusesPendingConnectAfterRecoveryFailure(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	var operationIDs []string
	var connectCalls int
	inner := &fakeUICore{connect: func(_ context.Context, req v1.ConnectRequest) (v1.Connection, error) {
		connectCalls++
		operationIDs = append(operationIDs, req.OperationID)
		if connectCalls == 1 {
			return v1.Connection{}, unavailableStage(coreclient.UnavailableStageReadResponse)
		}
		return v1.Connection{ID: "conn_manual_reconcile"}, nil
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		if recoverCalls == 1 {
			return recoveryErr
		}
		return nil
	})

	_, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if !errors.Is(err, ErrConnectOutcomeUnknown) || !errors.Is(err, recoveryErr) {
		t.Fatalf("first Connect() error = %v; want unknown outcome and recovery failure", err)
	}
	connection, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if err != nil {
		t.Fatalf("manual reconciliation Connect() error = %v", err)
	}
	if connection.ID != "conn_manual_reconcile" {
		t.Fatalf("connection = %#v", connection)
	}
	if len(operationIDs) != 2 || operationIDs[0] == "" || operationIDs[0] != operationIDs[1] {
		t.Fatalf("operation IDs = %#v; want the same non-empty ID", operationIDs)
	}
}

func TestRecoveringCorePendingConnectBlocksDifferentDevice(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	inner := &fakeUICore{connect: func(context.Context, v1.ConnectRequest) (v1.Connection, error) {
		return v1.Connection{}, unavailableStage(coreclient.UnavailableStageReadResponse)
	}}
	core := newRecoveringCore(inner, func(context.Context) error { return recoveryErr })

	_, _ = core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer-a"})
	_, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer-b"})
	if !errors.Is(err, ErrConnectOutcomeUnknown) {
		t.Fatalf("different-device Connect() error = %v; want ErrConnectOutcomeUnknown", err)
	}
}

func TestRecoveringCoreRetriesTerminalWriteBeforeRequestWrite(t *testing.T) {
	var writeCalls int
	var operationID string
	inner := &fakeUICore{writeTerminal: func(_ context.Context, req v1.TerminalWriteRequest) error {
		writeCalls++
		if operationID == "" {
			operationID = req.OperationID
		} else if operationID != req.OperationID {
			t.Fatalf("terminal operation ID changed: %q != %q", req.OperationID, operationID)
		}
		if writeCalls == 1 {
			return unavailableStage(coreclient.UnavailableStageSetDeadline)
		}
		return nil
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	if err := core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "c", Data: []byte("x")}); err != nil {
		t.Fatalf("WriteTerminal() error = %v", err)
	}
	if writeCalls != 2 || recoverCalls != 1 {
		t.Fatalf("write calls = %d, recovery calls = %d; want 2, 1", writeCalls, recoverCalls)
	}
}

func TestRecoveringCoreReplaysTerminalWriteAfterRequestWrite(t *testing.T) {
	var writeCalls int
	var operationID string
	inner := &fakeUICore{writeTerminal: func(_ context.Context, req v1.TerminalWriteRequest) error {
		writeCalls++
		if operationID == "" {
			operationID = req.OperationID
		} else if operationID != req.OperationID {
			t.Fatalf("terminal operation ID changed: %q != %q", req.OperationID, operationID)
		}
		if writeCalls == 1 {
			return unavailableStage(coreclient.UnavailableStageWriteRequest)
		}
		return nil
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	err := core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "c", Data: []byte("x")})
	if err != nil {
		t.Fatalf("WriteTerminal() error = %v", err)
	}
	if writeCalls != 2 || recoverCalls != 1 {
		t.Fatalf("write calls = %d, recovery calls = %d; want 2, 1", writeCalls, recoverCalls)
	}
}

func TestRecoveringCoreMarksRetryUnknownIfSecondConnectWasWritten(t *testing.T) {
	var connectCalls int
	var operationID string
	inner := &fakeUICore{connect: func(_ context.Context, req v1.ConnectRequest) (v1.Connection, error) {
		connectCalls++
		if operationID == "" {
			operationID = req.OperationID
		} else if operationID != req.OperationID {
			t.Fatalf("operation ID changed: %q != %q", req.OperationID, operationID)
		}
		if connectCalls == 1 {
			return v1.Connection{}, unavailableStage(coreclient.UnavailableStageDial)
		}
		return v1.Connection{}, unavailableStage(coreclient.UnavailableStageReadResponse)
	}}
	core := newRecoveringCore(inner, func(context.Context) error { return nil })

	_, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if !errors.Is(err, ErrConnectOutcomeUnknown) {
		t.Fatalf("Connect() error = %v; want ErrConnectOutcomeUnknown", err)
	}
	if connectCalls != 2 {
		t.Fatalf("connect calls = %d; want 2", connectCalls)
	}
}

func TestRecoveringCoreAmbiguousTerminalMutationPreservesRecoveryFailure(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	inner := &fakeUICore{writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
		return unavailableStage(coreclient.UnavailableStageReadResponse)
	}}
	core := newRecoveringCore(inner, func(context.Context) error { return recoveryErr })

	err := core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "c", Data: []byte("x")})
	if !errors.Is(err, ErrTerminalWriteOutcomeUnknown) || !errors.Is(err, recoveryErr) {
		t.Fatalf("WriteTerminal() error = %v; want unknown outcome and recovery failure", err)
	}
}

func TestRecoveringCorePreWriteMutationReturnsRecoveryFailure(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	inner := &fakeUICore{connect: func(context.Context, v1.ConnectRequest) (v1.Connection, error) {
		return v1.Connection{}, unavailableStage(coreclient.UnavailableStageDial)
	}}
	core := newRecoveringCore(inner, func(context.Context) error { return recoveryErr })

	_, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if !errors.Is(err, recoveryErr) {
		t.Fatalf("Connect() error = %v; want recovery failure", err)
	}
	if errors.Is(err, ErrConnectOutcomeUnknown) {
		t.Fatalf("Connect() error = %v; pre-write failure must not be outcome-unknown", err)
	}
}

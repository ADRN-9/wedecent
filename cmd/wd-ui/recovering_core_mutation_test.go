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
	inner := &fakeUICore{connect: func(context.Context, v1.ConnectRequest) (v1.Connection, error) {
		connectCalls++
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

func TestRecoveringCoreRetriesTerminalWriteBeforeRequestWrite(t *testing.T) {
	var writeCalls int
	inner := &fakeUICore{writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
		writeCalls++
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

func TestRecoveringCoreMarksConnectUnknownAfterRequestWrite(t *testing.T) {
	var connectCalls int
	inner := &fakeUICore{connect: func(context.Context, v1.ConnectRequest) (v1.Connection, error) {
		connectCalls++
		return v1.Connection{}, unavailableStage(coreclient.UnavailableStageReadResponse)
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		return nil
	})

	_, err := core.Connect(context.Background(), v1.ConnectRequest{DeviceID: "peer"})
	if !errors.Is(err, ErrConnectOutcomeUnknown) {
		t.Fatalf("Connect() error = %v; want ErrConnectOutcomeUnknown", err)
	}
	if !errors.Is(err, coreclient.ErrUnavailable) {
		t.Fatalf("Connect() error = %v; want wrapped ErrUnavailable", err)
	}
	if connectCalls != 1 || recoverCalls != 1 {
		t.Fatalf("connect calls = %d, recovery calls = %d; want 1, 1", connectCalls, recoverCalls)
	}
}

func TestRecoveringCoreMarksTerminalWriteUnknownAfterRequestWrite(t *testing.T) {
	var writeCalls int
	inner := &fakeUICore{writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
		writeCalls++
		return unavailableStage(coreclient.UnavailableStageWriteRequest)
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
	if !errors.Is(err, coreclient.ErrUnavailable) {
		t.Fatalf("WriteTerminal() error = %v; want wrapped ErrUnavailable", err)
	}
	if writeCalls != 1 || recoverCalls != 1 {
		t.Fatalf("write calls = %d, recovery calls = %d; want 1, 1", writeCalls, recoverCalls)
	}
}

func TestRecoveringCoreMarksRetryUnknownIfSecondConnectWasWritten(t *testing.T) {
	var connectCalls int
	inner := &fakeUICore{connect: func(context.Context, v1.ConnectRequest) (v1.Connection, error) {
		connectCalls++
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

func TestRecoveringCoreAmbiguousMutationPreservesRecoveryFailure(t *testing.T) {
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

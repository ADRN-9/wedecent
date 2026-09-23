package main

import (
	"context"
	"errors"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestRecoveringCoreConnectTimeoutAfterWriteIsOutcomeUnknown(t *testing.T) {
	var connectCalls int
	inner := &fakeUICore{connect: func(context.Context, v1.ConnectRequest) (v1.Connection, error) {
		connectCalls++
		return v1.Connection{}, errors.Join(
			context.DeadlineExceeded,
			&coreclient.UnavailableError{Stage: coreclient.UnavailableStageReadResponse},
		)
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
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect() error = %v; want timeout cause preserved", err)
	}
	if connectCalls != 1 || recoverCalls != 1 {
		t.Fatalf("connect calls = %d, recovery calls = %d; want 1, 1", connectCalls, recoverCalls)
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

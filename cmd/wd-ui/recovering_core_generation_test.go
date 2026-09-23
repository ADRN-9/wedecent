package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestRecoveringCoreSkipsStaleRecoveryGeneration(t *testing.T) {
	var recoverCalls atomic.Int32
	wrapped := newRecoveringCore(&fakeUICore{}, func(context.Context) error {
		recoverCalls.Add(1)
		return nil
	})
	core, ok := wrapped.(*recoveringCore)
	if !ok {
		t.Fatal("newRecoveringCore() did not return recoveringCore")
	}

	observed := core.recoveryGeneration()
	if err := core.recoverOnce(context.Background(), observed); err != nil {
		t.Fatalf("first recoverOnce() error = %v", err)
	}
	if got := recoverCalls.Load(); got != 1 {
		t.Fatalf("recovery calls after first recovery = %d; want 1", got)
	}
	if got := core.recoveryGeneration(); got == observed {
		t.Fatalf("generation = %d; want advancement from %d", got, observed)
	}

	if err := core.recoverOnce(context.Background(), observed); err != nil {
		t.Fatalf("stale recoverOnce() error = %v", err)
	}
	if got := recoverCalls.Load(); got != 1 {
		t.Fatalf("stale observation triggered recovery; calls = %d, want 1", got)
	}
}

func TestRecoveringCoreFailedRecoveryDoesNotAdvanceGeneration(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	var recoverCalls atomic.Int32
	wrapped := newRecoveringCore(&fakeUICore{}, func(context.Context) error {
		if recoverCalls.Add(1) == 1 {
			return recoveryErr
		}
		return nil
	})
	core := wrapped.(*recoveringCore)
	observed := core.recoveryGeneration()

	if err := core.recoverOnce(context.Background(), observed); !errors.Is(err, recoveryErr) {
		t.Fatalf("first recoverOnce() error = %v; want recovery failure", err)
	}
	if got := core.recoveryGeneration(); got != observed {
		t.Fatalf("failed recovery advanced generation to %d; want %d", got, observed)
	}
	if err := core.recoverOnce(context.Background(), observed); err != nil {
		t.Fatalf("second recoverOnce() error = %v", err)
	}
	if got := recoverCalls.Load(); got != 2 {
		t.Fatalf("recovery calls = %d; want 2", got)
	}
}

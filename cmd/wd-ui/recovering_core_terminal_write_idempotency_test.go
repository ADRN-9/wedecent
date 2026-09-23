package main

import (
	"context"
	"errors"
	"testing"
	"time"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestRecoveringCoreReusesPendingTerminalWriteAfterRecoveryFailure(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	var operationIDs []string
	var calls int
	inner := &fakeUICore{writeTerminal: func(_ context.Context, req v1.TerminalWriteRequest) error {
		calls++
		operationIDs = append(operationIDs, req.OperationID)
		if calls == 1 {
			return unavailableStage(coreclient.UnavailableStageReadResponse)
		}
		return nil
	}}
	var recoverCalls int
	core := newRecoveringCore(inner, func(context.Context) error {
		recoverCalls++
		if recoverCalls == 1 {
			return recoveryErr
		}
		return nil
	})
	req := v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("same payload")}

	err := core.WriteTerminal(context.Background(), req)
	if !errors.Is(err, ErrTerminalWriteOutcomeUnknown) || !errors.Is(err, recoveryErr) {
		t.Fatalf("first WriteTerminal() error = %v; want unknown outcome and recovery failure", err)
	}
	if err := core.WriteTerminal(context.Background(), req); err != nil {
		t.Fatalf("manual reconciliation WriteTerminal() error = %v", err)
	}
	if len(operationIDs) != 2 || operationIDs[0] == "" || operationIDs[0] != operationIDs[1] {
		t.Fatalf("operation IDs = %#v; want same non-empty ID", operationIDs)
	}
}

func TestRecoveringCorePendingTerminalWriteBlocksChangedPayload(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	var calls int
	inner := &fakeUICore{writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
		calls++
		return unavailableStage(coreclient.UnavailableStageReadResponse)
	}}
	core := newRecoveringCore(inner, func(context.Context) error { return recoveryErr })

	_ = core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("first")})
	err := core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("different")})
	if !errors.Is(err, ErrTerminalWriteOutcomeUnknown) {
		t.Fatalf("changed payload error = %v; want ErrTerminalWriteOutcomeUnknown", err)
	}
	if calls != 1 {
		t.Fatalf("inner WriteTerminal calls = %d; want 1", calls)
	}
}

func TestRecoveringCoreExpiredPendingTerminalWriteFailsClosed(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	var calls int
	inner := &fakeUICore{writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
		calls++
		return unavailableStage(coreclient.UnavailableStageReadResponse)
	}}
	wrapped := newRecoveringCore(inner, func(context.Context) error { return recoveryErr })
	core := wrapped.(*recoveringCore)
	req := v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("payload")}

	_ = core.WriteTerminal(context.Background(), req)
	core.mu.Lock()
	pending := core.pendingTerminalWrites[req.ConnectionID]
	pending.expiresAt = time.Now().Add(-time.Second)
	core.pendingTerminalWrites[req.ConnectionID] = pending
	core.mu.Unlock()

	err := core.WriteTerminal(context.Background(), req)
	if !errors.Is(err, ErrTerminalWriteOutcomeUnknown) {
		t.Fatalf("expired pending write error = %v; want ErrTerminalWriteOutcomeUnknown", err)
	}
	if calls != 1 {
		t.Fatalf("inner WriteTerminal calls = %d; want 1", calls)
	}
}

func TestRecoveringCoreConnectionGoneClearsPendingTerminalWrite(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	var writes int
	inner := &fakeUICore{
		writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
			writes++
			if writes == 1 {
				return unavailableStage(coreclient.UnavailableStageReadResponse)
			}
			return nil
		},
		disconnect: func(context.Context, v1.DisconnectRequest) error {
			return &coreclient.RemoteError{Code: ipc.ErrorConnectionNotFound, Message: "connection not found"}
		},
	}
	core := newRecoveringCore(inner, func(context.Context) error { return recoveryErr })

	_ = core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("old")})
	if err := core.Disconnect(context.Background(), v1.DisconnectRequest{ConnectionID: "conn-a"}); !coreclient.IsConnectionGone(err) {
		t.Fatalf("Disconnect() error = %v; want connection gone", err)
	}
	if err := core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("new")}); err != nil {
		t.Fatalf("write after pending clear error = %v", err)
	}
	if writes != 2 {
		t.Fatalf("inner WriteTerminal calls = %d; want 2", writes)
	}
}

func TestRecoveringCoreTerminalOperationFailureStaysPending(t *testing.T) {
	var operationIDs []string
	inner := &fakeUICore{writeTerminal: func(_ context.Context, req v1.TerminalWriteRequest) error {
		operationIDs = append(operationIDs, req.OperationID)
		return &coreclient.RemoteError{Code: ipc.ErrorTerminalFailed, Message: "terminal operation failed"}
	}}
	core := newRecoveringCore(inner, func(context.Context) error {
		t.Fatal("application-level terminal failure must not launch recovery")
		return nil
	})
	req := v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("payload")}

	for i := 0; i < 2; i++ {
		err := core.WriteTerminal(context.Background(), req)
		if !errors.Is(err, ErrTerminalWriteOutcomeUnknown) || !coreclient.IsRemoteCode(err, ipc.ErrorTerminalFailed) {
			t.Fatalf("WriteTerminal() error = %v; want ambiguous terminal failure", err)
		}
	}
	if len(operationIDs) != 2 || operationIDs[0] == "" || operationIDs[0] != operationIDs[1] {
		t.Fatalf("operation IDs = %#v; want stable pending replay key", operationIDs)
	}
}

func TestRecoveringCoreTerminalUnavailableClearsPending(t *testing.T) {
	var operationIDs []string
	var calls int
	inner := &fakeUICore{writeTerminal: func(_ context.Context, req v1.TerminalWriteRequest) error {
		calls++
		operationIDs = append(operationIDs, req.OperationID)
		if calls == 1 {
			return &coreclient.RemoteError{Code: ipc.ErrorTerminalUnavailable, Message: "terminal stream is unavailable"}
		}
		return nil
	}}
	core := newRecoveringCore(inner, func(context.Context) error {
		t.Fatal("terminal_unavailable must not launch recovery")
		return nil
	})
	req := v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("payload")}

	err := core.WriteTerminal(context.Background(), req)
	if !coreclient.IsRemoteCode(err, ipc.ErrorTerminalUnavailable) || errors.Is(err, ErrTerminalWriteOutcomeUnknown) {
		t.Fatalf("first WriteTerminal() error = %v; want definitive terminal_unavailable", err)
	}
	if err := core.WriteTerminal(context.Background(), req); err != nil {
		t.Fatalf("second WriteTerminal() error = %v", err)
	}
	if len(operationIDs) != 2 || operationIDs[0] == "" || operationIDs[1] == "" || operationIDs[0] == operationIDs[1] {
		t.Fatalf("operation IDs = %#v; definitive failure should clear pending key", operationIDs)
	}
}

func TestRecoveringCoreAmbiguousWriteRemainsUnknownAfterRecoveredConnectionGone(t *testing.T) {
	var operationIDs []string
	var calls int
	inner := &fakeUICore{writeTerminal: func(_ context.Context, req v1.TerminalWriteRequest) error {
		calls++
		operationIDs = append(operationIDs, req.OperationID)
		if calls == 1 {
			return unavailableStage(coreclient.UnavailableStageReadResponse)
		}
		return &coreclient.RemoteError{Code: ipc.ErrorConnectionNotFound, Message: "connection not found"}
	}}
	core := newRecoveringCore(inner, func(context.Context) error { return nil })

	err := core.WriteTerminal(context.Background(), v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("payload")})
	if !errors.Is(err, ErrTerminalWriteOutcomeUnknown) || !coreclient.IsConnectionGone(err) {
		t.Fatalf("WriteTerminal() error = %v; want ambiguous outcome preserving connection_not_found", err)
	}
	if len(operationIDs) != 2 || operationIDs[0] == "" || operationIDs[0] != operationIDs[1] {
		t.Fatalf("operation IDs = %#v; want same replay key across recovery", operationIDs)
	}
}

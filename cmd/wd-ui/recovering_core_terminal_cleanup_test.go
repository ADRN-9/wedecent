package main

import (
	"context"
	"errors"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestRecoveringCoreConnectionGoneAfterAmbiguousWriteClearsPendingMetadata(t *testing.T) {
	var calls int
	inner := &fakeUICore{writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
		calls++
		if calls == 1 {
			return unavailableStage(coreclient.UnavailableStageReadResponse)
		}
		return &coreclient.RemoteError{Code: ipc.ErrorConnectionNotFound, Message: "connection not found"}
	}}
	wrapped := newRecoveringCore(inner, func(context.Context) error { return nil })
	core := wrapped.(*recoveringCore)
	req := v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("payload")}

	err := core.WriteTerminal(context.Background(), req)
	if !errors.Is(err, ErrTerminalWriteOutcomeUnknown) || !coreclient.IsConnectionGone(err) {
		t.Fatalf("WriteTerminal() error = %v; want ambiguous connection_not_found", err)
	}
	core.mu.Lock()
	_, pending := core.pendingTerminalWrites[req.ConnectionID]
	core.mu.Unlock()
	if pending {
		t.Fatal("connection_not_found left stale pending terminal-write metadata")
	}
}

func TestRecoveringCoreNaturalTerminalCloseClearsPendingMetadata(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	inner := &fakeUICore{
		writeTerminal: func(context.Context, v1.TerminalWriteRequest) error {
			return unavailableStage(coreclient.UnavailableStageReadResponse)
		},
		readTerminal: func(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
			return v1.TerminalReadResult{Closed: true}, nil
		},
	}
	wrapped := newRecoveringCore(inner, func(context.Context) error { return recoveryErr })
	core := wrapped.(*recoveringCore)
	req := v1.TerminalWriteRequest{ConnectionID: "conn-a", Data: []byte("payload")}

	if err := core.WriteTerminal(context.Background(), req); !errors.Is(err, ErrTerminalWriteOutcomeUnknown) {
		t.Fatalf("WriteTerminal() error = %v; want ambiguous outcome", err)
	}
	if _, err := core.ReadTerminal(context.Background(), v1.TerminalReadRequest{ConnectionID: req.ConnectionID}); err != nil {
		t.Fatalf("ReadTerminal() error = %v", err)
	}
	core.mu.Lock()
	_, pending := core.pendingTerminalWrites[req.ConnectionID]
	core.mu.Unlock()
	if pending {
		t.Fatal("natural terminal close left stale pending terminal-write metadata")
	}
}

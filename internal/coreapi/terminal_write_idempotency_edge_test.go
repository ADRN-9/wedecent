package coreapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestTerminalWriteIdempotencyRejectsInvalidOperationIDs(t *testing.T) {
	inner := &idempotencyTerminalService{}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	for _, operationID := range []string{
		"contains space",
		"contains/slash",
		strings.Repeat("a", v1.MaxTerminalWriteOperationIDBytes+1),
	} {
		err := service.WriteTerminal(context.Background(), v1.TerminalWriteRequest{
			ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
			Data:         []byte("x"),
			OperationID:  operationID,
		})
		if !errors.Is(err, ErrInvalidTerminalRequest) {
			t.Fatalf("operation ID %q error = %v, want ErrInvalidTerminalRequest", operationID, err)
		}
	}
	if inner.writeCount() != 0 {
		t.Fatalf("inner WriteTerminal calls = %d, want 0", inner.writeCount())
	}
}

func TestTerminalWriteIdempotencyFollowerCancellationDoesNotPoisonLeader(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	inner := &idempotencyTerminalService{write: func(context.Context, v1.TerminalWriteRequest) error {
		close(started)
		<-release
		return nil
	}}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	req := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         []byte("payload"),
		OperationID:  "write_follower_cancel",
	}

	leaderDone := make(chan error, 1)
	go func() { leaderDone <- service.WriteTerminal(context.Background(), req) }()
	<-started

	followerCtx, cancel := context.WithCancel(context.Background())
	followerDone := make(chan error, 1)
	go func() { followerDone <- service.WriteTerminal(followerCtx, req) }()
	cancel()
	select {
	case err := <-followerDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("follower error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("follower did not unblock after cancellation")
	}

	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader error = %v", err)
	}
	if err := service.WriteTerminal(context.Background(), req); err != nil {
		t.Fatalf("replay error = %v", err)
	}
	if inner.writeCount() != 1 {
		t.Fatalf("inner WriteTerminal calls = %d, want 1", inner.writeCount())
	}
}

func TestTerminalWriteIdempotencyCopiesPayloadBeforeInnerCall(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	seen := make(chan string, 1)
	inner := &idempotencyTerminalService{write: func(_ context.Context, req v1.TerminalWriteRequest) error {
		close(entered)
		<-release
		seen <- string(req.Data)
		return nil
	}}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("original")
	req := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         data,
		OperationID:  "write_copy_payload",
	}
	done := make(chan error, 1)
	go func() { done <- service.WriteTerminal(context.Background(), req) }()
	<-entered
	copy(data, []byte("mutated!"))
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "original" {
		t.Fatalf("inner payload = %q, want original", got)
	}
}

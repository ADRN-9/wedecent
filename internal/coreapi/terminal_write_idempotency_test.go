package coreapi

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type idempotencyTerminalService struct {
	mu       sync.Mutex
	write    func(context.Context, v1.TerminalWriteRequest) error
	writes   int
	lastData []byte
}

func (s *idempotencyTerminalService) ReadTerminal(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	return v1.TerminalReadResult{}, nil
}

func (s *idempotencyTerminalService) ResizeTerminal(context.Context, v1.TerminalResizeRequest) error {
	return nil
}

func (s *idempotencyTerminalService) WriteTerminal(ctx context.Context, req v1.TerminalWriteRequest) error {
	s.mu.Lock()
	s.writes++
	s.lastData = append(s.lastData[:0], req.Data...)
	fn := s.write
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return nil
}

func (s *idempotencyTerminalService) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func TestTerminalWriteIdempotencyReplaysCompletedResult(t *testing.T) {
	inner := &idempotencyTerminalService{}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	req := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         []byte("echo hello\r"),
		OperationID:  "write_replay_1",
	}

	if err := service.WriteTerminal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := service.WriteTerminal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if inner.writeCount() != 1 {
		t.Fatalf("inner WriteTerminal calls = %d, want 1", inner.writeCount())
	}
}

func TestTerminalWriteIdempotencyCoalescesConcurrentDuplicate(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	inner := &idempotencyTerminalService{write: func(ctx context.Context, _ v1.TerminalWriteRequest) error {
		once.Do(func() { close(started) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	}}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	req := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         []byte("pwd\r"),
		OperationID:  "write_concurrent_1",
	}

	errs := make(chan error, 2)
	go func() { errs <- service.WriteTerminal(context.Background(), req) }()
	<-started
	go func() { errs <- service.WriteTerminal(context.Background(), req) }()
	close(release)

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if inner.writeCount() != 1 {
		t.Fatalf("inner WriteTerminal calls = %d, want 1", inner.writeCount())
	}
}

func TestTerminalWriteIdempotencyRejectsPayloadAlias(t *testing.T) {
	inner := &idempotencyTerminalService{}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	base := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         []byte("first\r"),
		OperationID:  "write_alias_payload",
	}
	if err := service.WriteTerminal(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.Data = []byte("second\r")
	if err := service.WriteTerminal(context.Background(), changed); !errors.Is(err, ErrInvalidTerminalRequest) {
		t.Fatalf("payload alias error = %v, want ErrInvalidTerminalRequest", err)
	}
	if inner.writeCount() != 1 {
		t.Fatalf("inner WriteTerminal calls = %d, want 1", inner.writeCount())
	}
}

func TestTerminalWriteIdempotencyRejectsConnectionAlias(t *testing.T) {
	inner := &idempotencyTerminalService{}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	base := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         []byte("same\r"),
		OperationID:  "write_alias_connection",
	}
	if err := service.WriteTerminal(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.ConnectionID = "conn_zyxwvutsrqponmlkjihgfedc"
	if err := service.WriteTerminal(context.Background(), changed); !errors.Is(err, ErrInvalidTerminalRequest) {
		t.Fatalf("connection alias error = %v, want ErrInvalidTerminalRequest", err)
	}
	if inner.writeCount() != 1 {
		t.Fatalf("inner WriteTerminal calls = %d, want 1", inner.writeCount())
	}
}

func TestTerminalWriteIdempotencyCachesCanceledOutcome(t *testing.T) {
	inner := &idempotencyTerminalService{write: func(context.Context, v1.TerminalWriteRequest) error {
		return context.Canceled
	}}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	req := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         []byte("maybe-delivered\r"),
		OperationID:  "write_canceled_1",
	}
	if err := service.WriteTerminal(context.Background(), req); !errors.Is(err, context.Canceled) {
		t.Fatalf("first error = %v, want context.Canceled", err)
	}
	if err := service.WriteTerminal(context.Background(), req); !errors.Is(err, context.Canceled) {
		t.Fatalf("replay error = %v, want cached context.Canceled", err)
	}
	if inner.writeCount() != 1 {
		t.Fatalf("inner WriteTerminal calls = %d, want 1", inner.writeCount())
	}
}

func TestTerminalWriteIdempotencyLegacyEmptyOperationIDDoesNotDeduplicate(t *testing.T) {
	inner := &idempotencyTerminalService{}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	req := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         []byte("legacy\r"),
	}
	if err := service.WriteTerminal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := service.WriteTerminal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if inner.writeCount() != 2 {
		t.Fatalf("inner WriteTerminal calls = %d, want 2", inner.writeCount())
	}
}

func TestTerminalWriteIdempotencyPrunesExpiredResult(t *testing.T) {
	inner := &idempotencyTerminalService{}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	service.retention = time.Minute
	req := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         []byte("expiry\r"),
		OperationID:  "write_expire_1",
	}
	if err := service.WriteTerminal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if err := service.WriteTerminal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if inner.writeCount() != 2 {
		t.Fatalf("inner WriteTerminal calls = %d, want 2 after expiry", inner.writeCount())
	}
}

func TestTerminalWriteIdempotencyCacheExhaustionFailsClosed(t *testing.T) {
	inner := &idempotencyTerminalService{}
	service, err := NewTerminalWriteIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	service.maxEntries = 1
	first := v1.TerminalWriteRequest{
		ConnectionID: "conn_abcdefghijklmnopqrstuvwx",
		Data:         []byte("first\r"),
		OperationID:  "write_capacity_1",
	}
	if err := service.WriteTerminal(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.OperationID = "write_capacity_2"
	if err := service.WriteTerminal(context.Background(), second); !errors.Is(err, ErrTerminalUnavailable) {
		t.Fatalf("cache exhaustion error = %v, want ErrTerminalUnavailable", err)
	}
	if inner.writeCount() != 1 {
		t.Fatalf("inner WriteTerminal calls = %d, want 1", inner.writeCount())
	}
}

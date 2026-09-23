package coreapi

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type idempotencyConnectionService struct {
	mu         sync.Mutex
	connect    func(context.Context, v1.ConnectRequest) (v1.Connection, error)
	connects   int
	disconnect int
}

func (s *idempotencyConnectionService) Connect(ctx context.Context, req v1.ConnectRequest) (v1.Connection, error) {
	s.mu.Lock()
	s.connects++
	fn := s.connect
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	return v1.Connection{ID: "conn_default", DeviceID: req.DeviceID, State: v1.ConnectionStateConnected}, nil
}

func (s *idempotencyConnectionService) Disconnect(context.Context, v1.DisconnectRequest) error {
	s.mu.Lock()
	s.disconnect++
	s.mu.Unlock()
	return nil
}

func (s *idempotencyConnectionService) connectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connects
}

func TestConnectIdempotencyReplaysCompletedResult(t *testing.T) {
	inner := &idempotencyConnectionService{}
	service, err := NewConnectIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	req := v1.ConnectRequest{DeviceID: "wd_dest0000000000", OperationID: "op_replay_1"}

	first, err := service.Connect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Connect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("replayed result = %#v, want %#v", second, first)
	}
	if inner.connectCount() != 1 {
		t.Fatalf("inner Connect calls = %d, want 1", inner.connectCount())
	}
}

func TestConnectIdempotencyCoalescesConcurrentDuplicate(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	inner := &idempotencyConnectionService{connect: func(ctx context.Context, req v1.ConnectRequest) (v1.Connection, error) {
		once.Do(func() { close(started) })
		select {
		case <-ctx.Done():
			return v1.Connection{}, ctx.Err()
		case <-release:
			return v1.Connection{ID: "conn_shared", DeviceID: req.DeviceID, State: v1.ConnectionStateConnected}, nil
		}
	}}
	service, err := NewConnectIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	req := v1.ConnectRequest{DeviceID: "wd_dest0000000000", OperationID: "op_concurrent_1"}

	results := make(chan v1.Connection, 2)
	errs := make(chan error, 2)
	go func() {
		result, err := service.Connect(context.Background(), req)
		results <- result
		errs <- err
	}()
	<-started
	go func() {
		result, err := service.Connect(context.Background(), req)
		results <- result
		errs <- err
	}()
	close(release)

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		if result := <-results; result.ID != "conn_shared" {
			t.Fatalf("result = %#v", result)
		}
	}
	if inner.connectCount() != 1 {
		t.Fatalf("inner Connect calls = %d, want 1", inner.connectCount())
	}
}

func TestConnectIdempotencyRejectsOperationAliasAcrossDevices(t *testing.T) {
	inner := &idempotencyConnectionService{}
	service, err := NewConnectIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_dest0000000000", OperationID: "op_alias_1"}); err != nil {
		t.Fatal(err)
	}
	_, err = service.Connect(context.Background(), v1.ConnectRequest{DeviceID: "wd_other000000000", OperationID: "op_alias_1"})
	if !errors.Is(err, ErrInvalidConnectionRequest) {
		t.Fatalf("alias error = %v, want ErrInvalidConnectionRequest", err)
	}
	if inner.connectCount() != 1 {
		t.Fatalf("inner Connect calls = %d, want 1", inner.connectCount())
	}
}

func TestConnectIdempotencyLegacyEmptyOperationIDDoesNotDeduplicate(t *testing.T) {
	inner := &idempotencyConnectionService{}
	service, err := NewConnectIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	req := v1.ConnectRequest{DeviceID: "wd_dest0000000000"}
	if _, err := service.Connect(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Connect(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if inner.connectCount() != 2 {
		t.Fatalf("inner Connect calls = %d, want 2", inner.connectCount())
	}
}

func TestConnectIdempotencyCanceledLeaderDoesNotPoisonFollower(t *testing.T) {
	firstStarted := make(chan struct{})
	var calls int
	var mu sync.Mutex
	inner := &idempotencyConnectionService{connect: func(ctx context.Context, req v1.ConnectRequest) (v1.Connection, error) {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		if call == 1 {
			close(firstStarted)
			<-ctx.Done()
			return v1.Connection{}, ctx.Err()
		}
		return v1.Connection{ID: "conn_after_cancel", DeviceID: req.DeviceID, State: v1.ConnectionStateConnected}, nil
	}}
	service, err := NewConnectIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	req := v1.ConnectRequest{DeviceID: "wd_dest0000000000", OperationID: "op_cancel_1"}

	leaderCtx, cancel := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := service.Connect(leaderCtx, req)
		leaderDone <- err
	}()
	<-firstStarted

	followerDone := make(chan error, 1)
	go func() {
		result, err := service.Connect(context.Background(), req)
		if err == nil && result.ID != "conn_after_cancel" {
			err = errors.New("unexpected follower result")
		}
		followerDone <- err
	}()
	cancel()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	if err := <-followerDone; err != nil {
		t.Fatalf("follower error = %v", err)
	}
	if inner.connectCount() != 2 {
		t.Fatalf("inner Connect calls = %d, want 2", inner.connectCount())
	}
}

func TestConnectIdempotencyPrunesExpiredResults(t *testing.T) {
	inner := &idempotencyConnectionService{}
	service, err := NewConnectIdempotencyService(inner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 15, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	service.retention = time.Minute
	req := v1.ConnectRequest{DeviceID: "wd_dest0000000000", OperationID: "op_expire_1"}

	if _, err := service.Connect(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := service.Connect(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if inner.connectCount() != 2 {
		t.Fatalf("inner Connect calls = %d, want 2 after retention", inner.connectCount())
	}
}

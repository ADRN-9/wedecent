package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestRecoveringCoreLiveCallerCanReplaceCanceledLeader(t *testing.T) {
	var healthy atomic.Bool
	inner := &fakeUICore{getStatus: func(context.Context) (v1.Status, error) {
		if healthy.Load() {
			return v1.Status{DeviceID: "ready"}, nil
		}
		return v1.Status{}, unavailableForTest()
	}}

	firstStarted := make(chan struct{})
	unexpectedRecovery := errors.New("unexpected extra recovery attempt")
	var recoverCalls atomic.Int32
	core := newRecoveringCore(inner, func(ctx context.Context) error {
		switch recoverCalls.Add(1) {
		case 1:
			close(firstStarted)
			<-ctx.Done()
			return ctx.Err()
		case 2:
			healthy.Store(true)
			return nil
		default:
			return unexpectedRecovery
		}
	})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := core.GetStatus(leaderCtx)
		leaderDone <- err
	}()
	<-firstStarted

	followerDone := make(chan error, 1)
	go func() {
		_, err := core.GetStatus(context.Background())
		followerDone <- err
	}()

	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v; want context.Canceled", err)
	}
	if err := <-followerDone; err != nil {
		t.Fatalf("follower error = %v; want nil", err)
	}
	if got := recoverCalls.Load(); got != 2 {
		t.Fatalf("recovery calls = %d; want 2", got)
	}
}

package account

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitForRouteAuthorizationIssuedAtAlreadyActive(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	if err := waitForRouteAuthorizationIssuedAt(
		context.Background(),
		now,
		now.Add(-time.Second).UnixMilli(),
	); err != nil {
		t.Fatalf("wait for already-active route authorization: %v", err)
	}
}

func TestWaitForRouteAuthorizationIssuedAtFuture(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	if err := waitForRouteAuthorizationIssuedAt(
		context.Background(),
		now,
		now.Add(5*time.Millisecond).UnixMilli(),
	); err != nil {
		t.Fatalf("wait for future route authorization: %v", err)
	}
}

func TestWaitForRouteAuthorizationIssuedAtHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	now := time.Now().UTC()
	err := waitForRouteAuthorizationIssuedAt(
		ctx,
		now,
		now.Add(time.Minute).UnixMilli(),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want context.Canceled", err)
	}
}

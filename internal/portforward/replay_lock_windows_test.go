//go:build windows

package portforward

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsReplayOSLockWaitHonorsCancellation(t *testing.T) {
	path := filepath.Join(newReplayTestDir(t), "replay.json")
	unlock, _, err := lockReplayFileOSContext(context.Background(), path, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unlock(); err != nil {
			t.Errorf("release OS replay lock: %v", err)
		}
	}()

	contention := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := lockReplayFileOSContext(ctx, path, path, func() {
			select {
			case contention <- struct{}{}:
			default:
			}
		})
		done <- err
	}()
	select {
	case <-contention:
	case <-time.After(2 * time.Second):
		t.Fatal("OS lock waiter did not report contention")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled OS lock error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OS lock waiter did not honor cancellation")
	}
}

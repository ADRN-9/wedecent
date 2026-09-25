//go:build windows

package session

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestWindowsResizeWatcherPollsAndStops(t *testing.T) {
	var calls atomic.Int32
	first := make(chan struct{}, 1)
	stop := watchResizeEvery(func() {
		calls.Add(1)
		select {
		case first <- struct{}{}:
		default:
		}
	}, 5*time.Millisecond)

	select {
	case <-first:
	case <-time.After(time.Second):
		stop()
		t.Fatal("Windows resize watcher did not poll")
	}

	stop()
	baseline := calls.Load()
	time.Sleep(25 * time.Millisecond)
	if got := calls.Load(); got != baseline {
		t.Fatalf("resize callbacks after stop = %d, want %d", got, baseline)
	}

	// Stop is deliberately idempotent because callers use it from defers.
	stop()
}

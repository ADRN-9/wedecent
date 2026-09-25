//go:build darwin

package session

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDarwinResizeWatcherStopsSynchronouslyAndIdempotently(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	stop := watchResize(func() {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
	})

	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		stop()
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		stop()
		t.Fatal("Darwin resize callback did not start")
	}

	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		close(release)
		t.Fatal("resize watcher stopped before in-flight callback exited")
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("resize watcher did not stop after callback exited")
	}
	stop()
}

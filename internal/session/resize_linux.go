//go:build linux

package session

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func watchResize(fn func()) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	stop := make(chan struct{})
	done := make(chan struct{})
	var stopOnce sync.Once

	go func() {
		defer close(done)
		for {
			select {
			case <-ch:
				fn()
			case <-stop:
				return
			}
		}
	}()

	return func() {
		stopOnce.Do(func() {
			signal.Stop(ch)
			close(stop)
		})
		<-done
	}
}

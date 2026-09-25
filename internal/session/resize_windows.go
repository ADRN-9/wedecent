//go:build windows

package session

import (
	"sync"
	"time"
)

const windowsResizePollInterval = 250 * time.Millisecond

func watchResize(fn func()) func() {
	return watchResizeEvery(fn, windowsResizePollInterval)
}

func watchResizeEvery(fn func(), interval time.Duration) func() {
	if interval <= 0 {
		interval = windowsResizePollInterval
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	var stopOnce sync.Once

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fn()
			case <-stop:
				return
			}
		}
	}()

	return func() {
		stopOnce.Do(func() { close(stop) })
		<-done
	}
}

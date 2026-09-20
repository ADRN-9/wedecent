// Package localserver owns the lifecycle around the Local Core API's protected
// local transport. It is transport-agnostic and never opens a network endpoint
// itself.
package localserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	DefaultMaxConcurrentRequests = 8
	DefaultRequestTimeout        = 5 * time.Second

	maxConcurrentRequests = 128
	maxRequestTimeout      = time.Minute
)

var ErrConfig = errors.New("core local server: invalid configuration")

// Config bounds local resource use. The zero value is intentionally invalid so
// callers must opt into explicit limits rather than accidentally running an
// unbounded server.
type Config struct {
	MaxConcurrentRequests int
	RequestTimeout        time.Duration
}

func DefaultConfig() Config {
	return Config{
		MaxConcurrentRequests: DefaultMaxConcurrentRequests,
		RequestTimeout:        DefaultRequestTimeout,
	}
}

func (c Config) validate() error {
	if c.MaxConcurrentRequests <= 0 || c.MaxConcurrentRequests > maxConcurrentRequests {
		return fmt.Errorf("%w: max concurrent requests must be between 1 and %d", ErrConfig, maxConcurrentRequests)
	}
	if c.RequestTimeout <= 0 || c.RequestTimeout > maxRequestTimeout {
		return fmt.Errorf("%w: request timeout must be between 1ns and %s", ErrConfig, maxRequestTimeout)
	}
	return nil
}

// ServeOneFunc handles one request/response exchange on an already-authenticated
// same-user local connection.
type ServeOneFunc func(context.Context, io.ReadWriter) error

// Serve accepts same-user local connections and runs exactly one bounded request
// on each connection.
//
// Serve owns listener for its lifetime and closes it before returning. Individual
// request errors are intentionally isolated to their connection: malformed or
// otherwise failing requests must not terminate the Local Core process. Handler
// panics are contained to the affected connection. Request bodies and handler
// errors are never logged here.
//
// Cancellation closes the listener and all active connections, then waits for
// request goroutines to exit. A parent-context cancellation is a clean shutdown
// and returns nil.
func Serve(ctx context.Context, listener net.Listener, serveOne ServeOneFunc, cfg Config) error {
	if ctx == nil || listener == nil || serveOne == nil {
		return ErrConfig
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = listener.Close()
		return nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		activeMu sync.Mutex
		active   = make(map[net.Conn]struct{})
		workers  sync.WaitGroup
	)

	closeActive := func() {
		activeMu.Lock()
		connections := make([]net.Conn, 0, len(active))
		for conn := range active {
			connections = append(connections, conn)
		}
		activeMu.Unlock()

		for _, conn := range connections {
			_ = conn.Close()
		}
	}

	stopWatcher := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-runCtx.Done():
			_ = listener.Close()
			closeActive()
		case <-stopWatcher:
		}
	}()

	sem := make(chan struct{}, cfg.MaxConcurrentRequests)
	var serveErr error

acceptLoop:
	for {
		select {
		case sem <- struct{}{}:
		case <-runCtx.Done():
			break acceptLoop
		}

		conn, err := listener.Accept()
		if err != nil {
			<-sem
			if runCtx.Err() != nil {
				break acceptLoop
			}
			serveErr = fmt.Errorf("core local server: accept: %w", err)
			cancel()
			break acceptLoop
		}

		activeMu.Lock()
		active[conn] = struct{}{}
		activeMu.Unlock()

		if runCtx.Err() != nil {
			_ = conn.Close()
			activeMu.Lock()
			delete(active, conn)
			activeMu.Unlock()
			<-sem
			break acceptLoop
		}

		workers.Add(1)
		go func(conn net.Conn) {
			defer workers.Done()
			defer func() {
				activeMu.Lock()
				delete(active, conn)
				activeMu.Unlock()
				_ = conn.Close()
				<-sem
			}()
			defer func() {
				_ = recover()
			}()

			deadline := time.Now().Add(cfg.RequestTimeout)
			if err := conn.SetDeadline(deadline); err != nil {
				return
			}
			requestCtx, requestCancel := context.WithTimeout(runCtx, cfg.RequestTimeout)
			defer requestCancel()

			_ = serveOne(requestCtx, conn)
		}(conn)
	}

	cancel()
	_ = listener.Close()
	closeActive()
	workers.Wait()
	close(stopWatcher)
	<-watcherDone

	if ctx.Err() != nil {
		return nil
	}
	return serveErr
}

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type shutdownTestAddr string

func (a shutdownTestAddr) Network() string { return "test" }
func (a shutdownTestAddr) String() string  { return string(a) }

type immediateErrorListener struct {
	err error
}

func (l *immediateErrorListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *immediateErrorListener) Close() error              { return nil }
func (l *immediateErrorListener) Addr() net.Addr            { return shutdownTestAddr("immediate") }

type delayedCloseListener struct {
	closeOnce sync.Once
	closed    chan struct{}
	release   chan struct{}
}

func newDelayedCloseListener() *delayedCloseListener {
	return &delayedCloseListener{
		closed:  make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (l *delayedCloseListener) Accept() (net.Conn, error) {
	<-l.closed
	<-l.release
	return nil, net.ErrClosed
}

func (l *delayedCloseListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *delayedCloseListener) Addr() net.Addr {
	return shutdownTestAddr("delayed")
}

func TestAgentListenerSetServeWaitsForAllAcceptLoops(t *testing.T) {
	firstErr := errors.New("first listener failed")
	delayed := newDelayedCloseListener()

	set := &agentListenerSet{
		listeners: []agentListener{
			{
				role:           "first",
				listener:       &immediateErrorListener{err: firstErr},
				maxConnections: 1,
			},
			{
				role:           "delayed",
				listener:       delayed,
				maxConnections: 1,
			},
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- set.serve(context.Background())
	}()

	select {
	case <-delayed.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("listener set did not close remaining listener")
	}

	select {
	case err := <-done:
		t.Fatalf("serve returned before remaining accept loop exited: %v", err)
	default:
	}

	close(delayed.release)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serve returned nil after fatal listener error")
		}
		if !strings.Contains(err.Error(), firstErr.Error()) {
			t.Fatalf("serve error = %v, want first listener error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after all accept loops exited")
	}
}

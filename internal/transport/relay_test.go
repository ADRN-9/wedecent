package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type deadlineObservedConn struct {
	net.Conn
	set chan struct{}
}

func (c *deadlineObservedConn) SetReadDeadline(deadline time.Time) error {
	select {
	case <-c.set:
	default:
		close(c.set)
	}
	return c.Conn.SetReadDeadline(deadline)
}

func TestReadRelayMessageHonorsContextCancellation(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	conn := &deadlineObservedConn{Conn: server, set: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := readRelayMessage(ctx, conn, time.Hour)
		done <- err
	}()
	select {
	case <-conn.set:
	case <-time.After(time.Second):
		t.Fatal("relay read did not install its deadline")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("read error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt relay read")
	}
}

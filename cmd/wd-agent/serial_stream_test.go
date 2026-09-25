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

func TestServeAgentSerialValidatesInputs(t *testing.T) {
	if err := serveAgentSerial(nil, "/dev/ttyACM0", func(net.Conn) {}); err == nil {
		t.Fatal("nil context unexpectedly succeeded")
	}
	if err := serveAgentSerial(context.Background(), "", func(net.Conn) {}); err == nil {
		t.Fatal("empty endpoint unexpectedly succeeded")
	}
	if err := serveAgentSerial(context.Background(), "/dev/ttyACM0", nil); err == nil {
		t.Fatal("nil handler unexpectedly succeeded")
	}
}

func TestServeAgentSerialOpenFailureIsFatal(t *testing.T) {
	oldDial := dialAgentSerial
	defer func() { dialAgentSerial = oldDial }()

	want := errors.New("device unavailable")
	dialAgentSerial = func(context.Context, string) (net.Conn, error) {
		return nil, want
	}

	called := false
	err := serveAgentSerial(context.Background(), "/dev/ttyACM0", func(net.Conn) {
		called = true
	})
	if err == nil || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("serve error = %v", err)
	}
	if called {
		t.Fatal("handler called after serial open failure")
	}
}

func TestServeAgentSerialCancellationClosesActiveStream(t *testing.T) {
	oldDial := dialAgentSerial
	defer func() { dialAgentSerial = oldDial }()

	serverConn, peerConn := net.Pipe()
	defer peerConn.Close()
	var mu sync.Mutex
	dials := 0
	dialAgentSerial = func(context.Context, string) (net.Conn, error) {
		mu.Lock()
		dials++
		mu.Unlock()
		return serverConn, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	handlerDone := make(chan error, 1)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serveAgentSerial(ctx, "/dev/ttyACM0", func(conn net.Conn) {
			close(started)
			buf := make([]byte, 1)
			_, err := conn.Read(buf)
			handlerDone <- err
		})
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("serial handler did not start")
	}
	cancel()

	select {
	case err := <-handlerDone:
		if err == nil {
			t.Fatal("active serial read returned nil after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("active serial stream was not closed on cancellation")
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serve after cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serial serve did not stop after cancellation")
	}

	mu.Lock()
	defer mu.Unlock()
	if dials != 1 {
		t.Fatalf("dial count = %d, want 1", dials)
	}
}

func TestServeAgentSerialBoundsSessionReopenRate(t *testing.T) {
	oldDial := dialAgentSerial
	defer func() { dialAgentSerial = oldDial }()

	var mu sync.Mutex
	var peers []net.Conn
	dialAgentSerial = func(context.Context, string) (net.Conn, error) {
		serverConn, peerConn := net.Pipe()
		mu.Lock()
		peers = append(peers, peerConn)
		mu.Unlock()
		return serverConn, nil
	}
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var callTimes []time.Time
	err := serveAgentSerial(ctx, "/dev/ttyACM0", func(net.Conn) {
		callTimes = append(callTimes, time.Now())
		if len(callTimes) == 2 {
			cancel()
		}
	})
	if err != nil {
		t.Fatalf("serve serial: %v", err)
	}
	if len(callTimes) != 2 {
		t.Fatalf("handler calls = %d, want 2", len(callTimes))
	}
	if elapsed := callTimes[1].Sub(callTimes[0]); elapsed < serialSessionReopenDelay-(25*time.Millisecond) {
		t.Fatalf("serial session reopened too quickly: %v", elapsed)
	}
}

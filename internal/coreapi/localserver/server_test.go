package localserver

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServeRejectsInvalidConfiguration(t *testing.T) {
	listener := newChannelListener(1)
	defer listener.Close()
	handler := func(context.Context, io.ReadWriter) error { return nil }

	cases := []Config{
		{},
		{MaxConcurrentRequests: 0, RequestTimeout: time.Second},
		{MaxConcurrentRequests: maxConcurrentRequests + 1, RequestTimeout: time.Second},
		{MaxConcurrentRequests: 1, RequestTimeout: 0},
		{MaxConcurrentRequests: 1, RequestTimeout: maxRequestTimeout + time.Nanosecond},
	}
	for _, cfg := range cases {
		if err := Serve(context.Background(), listener, handler, cfg); !errors.Is(err, ErrConfig) {
			t.Fatalf("Serve(%+v) error = %v, want ErrConfig", cfg, err)
		}
	}
}

func TestServeIsolatesRequestErrorAndPanic(t *testing.T) {
	listener := newChannelListener(3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	handler := func(_ context.Context, rw io.ReadWriter) error {
		switch calls.Add(1) {
		case 1:
			return errors.New("malformed request")
		case 2:
			panic("request panic")
		default:
			buf := make([]byte, 4)
			if _, err := io.ReadFull(rw, buf); err != nil {
				return err
			}
			if string(buf) != "ping" {
				return errors.New("unexpected payload")
			}
			_, err := rw.Write([]byte("pong"))
			return err
		}
	}

	serveDone := startServe(listener, ctx, handler, Config{MaxConcurrentRequests: 1, RequestTimeout: time.Second})

	clients := make([]net.Conn, 0, 3)
	for range 3 {
		serverConn, clientConn := net.Pipe()
		clients = append(clients, clientConn)
		listener.add(serverConn)
	}
	defer func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
	}()

	if _, err := clients[2].Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(clients[2], response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("response = %q", response)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("handler calls = %d, want 3", got)
	}

	cancel()
	if err := awaitServe(t, serveDone); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestServeBoundsConcurrentRequests(t *testing.T) {
	listener := newChannelListener(3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	handler := func(context.Context, io.ReadWriter) error {
		entered <- struct{}{}
		<-release
		return nil
	}
	serveDone := startServe(listener, ctx, handler, Config{MaxConcurrentRequests: 2, RequestTimeout: 2 * time.Second})

	clients := make([]net.Conn, 0, 3)
	for range 3 {
		serverConn, clientConn := net.Pipe()
		clients = append(clients, clientConn)
		listener.add(serverConn)
	}
	defer func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
	}()

	awaitSignal(t, entered)
	awaitSignal(t, entered)
	select {
	case <-entered:
		t.Fatal("third request entered before a concurrency slot was released")
	case <-time.After(75 * time.Millisecond):
	}

	close(release)
	awaitSignal(t, entered)

	cancel()
	if err := awaitServe(t, serveDone); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestServeAppliesPerRequestTimeout(t *testing.T) {
	listener := newChannelListener(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handlerDone := make(chan error, 1)
	handler := func(ctx context.Context, _ io.ReadWriter) error {
		<-ctx.Done()
		handlerDone <- ctx.Err()
		return ctx.Err()
	}
	serveDone := startServe(listener, ctx, handler, Config{MaxConcurrentRequests: 1, RequestTimeout: 30 * time.Millisecond})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	listener.add(serverConn)

	select {
	case err := <-handlerDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("handler context error = %v, want DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request timeout did not fire")
	}

	cancel()
	if err := awaitServe(t, serveDone); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestServeCancellationClosesBlockedConnection(t *testing.T) {
	listener := newChannelListener(1)
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	readDone := make(chan error, 1)
	handler := func(_ context.Context, rw io.ReadWriter) error {
		close(started)
		buf := make([]byte, 1)
		_, err := rw.Read(buf)
		readDone <- err
		return err
	}
	serveDone := startServe(listener, ctx, handler, Config{MaxConcurrentRequests: 1, RequestTimeout: time.Second})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	listener.add(serverConn)
	awaitSignal(t, started)

	cancel()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked read unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not close active connection")
	}
	if err := awaitServe(t, serveDone); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestServeReturnsUnexpectedAcceptError(t *testing.T) {
	listener := &errorListener{err: errors.New("accept failed")}
	err := Serve(
		context.Background(),
		listener,
		func(context.Context, io.ReadWriter) error { return nil },
		DefaultConfig(),
	)
	if err == nil || !strings.Contains(err.Error(), "accept failed") {
		t.Fatalf("Serve() error = %v, want wrapped accept error", err)
	}
}

func startServe(listener net.Listener, ctx context.Context, handler ServeOneFunc, cfg Config) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, listener, handler, cfg)
	}()
	return done
}

func awaitServe(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop")
		return nil
	}
}

func awaitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for signal")
	}
}

type channelListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newChannelListener(buffer int) *channelListener {
	return &channelListener{
		conns:  make(chan net.Conn, buffer),
		closed: make(chan struct{}),
	}
}

func (l *channelListener) add(conn net.Conn) {
	l.conns <- conn
}

func (l *channelListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.conns:
		return conn, nil
	}
}

func (l *channelListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *channelListener) Addr() net.Addr { return testAddr("local-core") }

type errorListener struct{ err error }

func (l *errorListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *errorListener) Close() error              { return nil }
func (l *errorListener) Addr() net.Addr            { return testAddr("error") }

type testAddr string

func (a testAddr) Network() string { return "local" }
func (a testAddr) String() string  { return string(a) }

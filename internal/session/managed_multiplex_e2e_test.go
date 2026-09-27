package session

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
)

type liveMuxPTY struct {
	mu       sync.Mutex
	written  bytes.Buffer
	cols     uint16
	rows     uint16
	output   chan []byte
	closed   chan struct{}
	closeOne sync.Once
}

func newLiveMuxPTY(cols, rows uint16) *liveMuxPTY {
	return &liveMuxPTY{
		cols:   cols,
		rows:   rows,
		output: make(chan []byte, 4),
		closed: make(chan struct{}),
	}
}

func (p *liveMuxPTY) Read(buf []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, io.EOF
	case data := <-p.output:
		if len(data) > len(buf) {
			return 0, errors.New("live mux test output exceeds read buffer")
		}
		return copy(buf, data), nil
	}
}

func (p *liveMuxPTY) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	return p.written.Write(data)
}

func (p *liveMuxPTY) Resize(cols, rows uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.closed:
		return io.ErrClosedPipe
	default:
	}
	p.cols, p.rows = cols, rows
	return nil
}

func (p *liveMuxPTY) Wait() error {
	<-p.closed
	return nil
}

func (p *liveMuxPTY) Close() error {
	p.closeOne.Do(func() { close(p.closed) })
	return nil
}

func (p *liveMuxPTY) emit(t *testing.T, data string) {
	t.Helper()
	select {
	case <-p.closed:
		t.Fatal("cannot emit output from closed PTY")
	case p.output <- []byte(data):
	case <-time.After(time.Second):
		t.Fatal("timed out injecting PTY output")
	}
}

func (p *liveMuxPTY) snapshot() (string, uint16, uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.written.String(), p.cols, p.rows
}

func TestManagedMultiplexLiveParentKeepsSiblingAfterChildClose(t *testing.T) {
	clientID, serverID, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	clientSide, serverSide := net.Pipe()
	dialer := &managedTestDialer{conn: clientSide}
	started := make(chan *liveMuxPTY, managedMuxMaxStreams)
	serverErr := make(chan error, 1)

	go func() {
		conn := tls.Server(serverSide, identity.ServerTLS(serverID))
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := conn.HandshakeContext(context.Background()); err != nil {
			serverErr <- err
			return
		}

		first, err := protocol.ReadFrame(conn)
		if err != nil {
			serverErr <- err
			return
		}
		if first.Type != protocol.TypeOpenAuthorizedSession {
			serverErr <- errors.New("managed multiplex client did not use authorized session open")
			return
		}
		var open protocol.OpenAuthorizedSession
		if err := protocol.ParseJSON(first.Payload, &open); err != nil {
			serverErr <- err
			return
		}
		if len(open.Capabilities) != 1 || open.Capabilities[0] != protocol.CapabilityTypedStreamsV1 {
			serverErr <- errors.New("managed multiplex client did not request typed-streams-v1")
			return
		}

		capabilities := []protocol.Capability{protocol.CapabilityTypedStreamsV1}
		accepted, err := sessionAcceptedFrame(capabilities)
		if err != nil {
			serverErr <- err
			return
		}

		var writeMu sync.Mutex
		writeFrame := func(frame protocol.Frame) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			return protocol.WriteFrame(conn, frame)
		}
		if err := writeFrame(accepted); err != nil {
			serverErr <- err
			return
		}

		typedServer := newTypedTerminalServerWithStarter(
			"/bin/sh",
			writeFrame,
			func(_ string, cols, rows uint16, _ string) (typedTerminalPTY, error) {
				pty := newLiveMuxPTY(cols, rows)
				started <- pty
				return pty, nil
			},
		)
		defer typedServer.CloseAll()

		for {
			frame, err := protocol.ReadFrame(conn)
			if err != nil {
				if errors.Is(err, io.EOF) {
					serverErr <- nil
				} else {
					serverErr <- err
				}
				return
			}
			handled, err := routeTypedTerminalFrame(capabilities, typedServer, frame)
			if handled {
				if err != nil {
					serverErr <- err
					return
				}
				continue
			}
			switch frame.Type {
			case protocol.TypePing:
				if err := writeFrame(protocol.Frame{Type: protocol.TypePong}); err != nil {
					serverErr <- err
					return
				}
			case protocol.TypeClose:
				typedServer.CloseAll()
				serverErr <- nil
				return
			default:
				serverErr <- errors.New("unexpected frame in live multiplex test server")
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := &Client{
		Identity:        clientID,
		Dialer:          dialer,
		ConnectionGrant: "header.payload.signature",
	}
	managed, err := client.OpenManagedMultiplexTerminal(ctx, peer, 80, 24, "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	defaultPTY := waitLiveMuxPTYStarted(t, started)

	streamA, err := managed.OpenTerminalStream(ctx, 90, 30, "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	ptyA := waitLiveMuxPTYStarted(t, started)
	streamB, err := managed.OpenTerminalStream(ctx, 100, 40, "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	ptyB := waitLiveMuxPTYStarted(t, started)
	if streamA == streamB || streamA == protocol.MinTypedStreamID || streamB == protocol.MinTypedStreamID {
		t.Fatalf("unexpected child ids: A=%d B=%d", streamA, streamB)
	}

	if err := managed.WriteTerminalStream(ctx, streamA, []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if err := managed.WriteTerminalStream(ctx, streamB, []byte("bravo")); err != nil {
		t.Fatal(err)
	}
	waitLiveMuxPTYState(t, ptyA, "alpha", 90, 30)
	waitLiveMuxPTYState(t, ptyB, "bravo", 100, 40)

	if err := managed.ResizeTerminalStream(ctx, streamA, 120, 41); err != nil {
		t.Fatal(err)
	}
	if err := managed.ResizeTerminalStream(ctx, streamB, 132, 52); err != nil {
		t.Fatal(err)
	}
	waitLiveMuxPTYState(t, ptyA, "alpha", 120, 41)
	waitLiveMuxPTYState(t, ptyB, "bravo", 132, 52)

	ptyA.emit(t, "out-a")
	data, closed, err := managed.ReadTerminalStream(ctx, streamA, 32)
	if err != nil || closed || string(data) != "out-a" {
		t.Fatalf("stream A read data=%q closed=%v err=%v", data, closed, err)
	}
	ptyB.emit(t, "out-b")
	data, closed, err = managed.ReadTerminalStream(ctx, streamB, 32)
	if err != nil || closed || string(data) != "out-b" {
		t.Fatalf("stream B read data=%q closed=%v err=%v", data, closed, err)
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := managed.CloseTerminalStream(closeCtx, streamA); err != nil {
		closeCancel()
		t.Fatalf("close child A: %v", err)
	}
	closeCancel()
	waitLiveMuxPTYClosed(t, ptyA)

	if err := managed.WriteTerminalStream(ctx, streamB, []byte("-still-open")); err != nil {
		t.Fatalf("sibling write after child close: %v", err)
	}
	waitLiveMuxPTYState(t, ptyB, "bravo-still-open", 132, 52)
	ptyB.emit(t, "out-b-2")
	data, closed, err = managed.ReadTerminalStream(ctx, streamB, 32)
	if err != nil || closed || string(data) != "out-b-2" {
		t.Fatalf("sibling read after child close data=%q closed=%v err=%v", data, closed, err)
	}

	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	waitLiveMuxPTYClosed(t, ptyB)
	waitLiveMuxPTYClosed(t, defaultPTY)
	if err := managed.WriteTerminalStream(context.Background(), streamB, []byte("after-parent-close")); err == nil {
		t.Fatal("parent close left child B writable")
	}
	waitLiveMuxServer(t, serverErr)
}

func TestManagedMultiplexLiveMalformedTypedFrameFailsParent(t *testing.T) {
	clientID, serverID, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	clientSide, serverSide := net.Pipe()
	dialer := &managedTestDialer{conn: clientSide}
	proceed := make(chan struct{})
	serverErr := make(chan error, 1)

	go func() {
		conn := tls.Server(serverSide, identity.ServerTLS(serverID))
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := conn.HandshakeContext(context.Background()); err != nil {
			serverErr <- err
			return
		}
		if _, err := protocol.ReadFrame(conn); err != nil {
			serverErr <- err
			return
		}
		accepted, err := sessionAcceptedFrame([]protocol.Capability{protocol.CapabilityTypedStreamsV1})
		if err != nil {
			serverErr <- err
			return
		}
		if err := protocol.WriteFrame(conn, accepted); err != nil {
			serverErr <- err
			return
		}
		open, err := protocol.ReadFrame(conn)
		if err != nil {
			serverErr <- err
			return
		}
		if open.Type != protocol.TypeStreamOpen || open.StreamID != protocol.MinTypedStreamID {
			serverErr <- errors.New("default typed child was not opened")
			return
		}
		payload, err := protocol.JSON(protocol.StreamAccepted{InitialWindow: typedTerminalReceiveWindow})
		if err != nil {
			serverErr <- err
			return
		}
		if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeStreamAccepted, StreamID: open.StreamID, Payload: payload}); err != nil {
			serverErr <- err
			return
		}
		<-proceed
		update, err := protocol.JSON(protocol.StreamWindowUpdate{Bytes: 1})
		if err != nil {
			serverErr <- err
			return
		}
		if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: 99, Payload: update}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := &Client{Identity: clientID, Dialer: dialer, ConnectionGrant: "header.payload.signature"}
	managed, err := client.OpenManagedMultiplexTerminal(ctx, peer, 80, 24, "xterm")
	if err != nil {
		t.Fatal(err)
	}
	close(proceed)

	select {
	case <-managed.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("malformed typed frame did not fail the parent session")
	}
	waitLiveMuxServer(t, serverErr)
}

func TestManagedMultiplexTerminalStreamCapacityIsBounded(t *testing.T) {
	streams := make(map[uint32]*managedMuxChild, managedMuxMaxStreams)
	for i := 0; i < managedMuxMaxStreams; i++ {
		id := protocol.MinTypedStreamID + uint32(i)
		streams[id] = newManagedMuxChild(id, true)
	}
	s := &ManagedMultiplexTerminal{
		typed:      true,
		streams:    streams,
		nextStream: protocol.MinTypedStreamID + uint32(managedMuxMaxStreams),
		allocated:  managedMuxMaxStreams,
		done:       make(chan struct{}),
	}
	if _, err := s.OpenTerminalStream(context.Background(), 80, 24, "xterm"); err == nil {
		t.Fatal("concurrent terminal stream limit was not enforced")
	}
	select {
	case <-s.done:
		t.Fatal("local capacity rejection closed the parent")
	default:
	}

	lifetime := &ManagedMultiplexTerminal{
		typed:      true,
		streams:    make(map[uint32]*managedMuxChild),
		nextStream: protocol.MinTypedStreamID,
		allocated:  managedMuxMaxAllocated,
		done:       make(chan struct{}),
	}
	if _, err := lifetime.OpenTerminalStream(context.Background(), 80, 24, "xterm"); err == nil {
		t.Fatal("lifetime terminal stream allocation limit was not enforced")
	}
}

func waitLiveMuxPTYStarted(t *testing.T, started <-chan *liveMuxPTY) *liveMuxPTY {
	t.Helper()
	select {
	case pty := <-started:
		return pty
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for typed terminal PTY")
		return nil
	}
}

func waitLiveMuxPTYState(t *testing.T, pty *liveMuxPTY, written string, cols, rows uint16) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		gotWritten, gotCols, gotRows := pty.snapshot()
		if gotWritten == written && gotCols == cols && gotRows == rows {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	gotWritten, gotCols, gotRows := pty.snapshot()
	t.Fatalf("PTY state written=%q size=%dx%d, want written=%q size=%dx%d", gotWritten, gotCols, gotRows, written, cols, rows)
}

func waitLiveMuxPTYClosed(t *testing.T, pty *liveMuxPTY) {
	t.Helper()
	select {
	case <-pty.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PTY close")
	}
}

func waitLiveMuxServer(t *testing.T, serverErr <-chan error) {
	t.Helper()
	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("live multiplex server failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for live multiplex server")
	}
}

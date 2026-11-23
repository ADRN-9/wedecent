package session

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/portforward"
	"wedecent.com/wedecent/internal/protocol"
)

func TestTypedPortForwardRejectsDataAfterHalfClose(t *testing.T) {
	streamID := protocol.MinTypedStreamID + 1
	recvCredit, err := newTypedStreamCredit(portForwardReceiveWindow)
	if err != nil {
		t.Fatal(err)
	}
	child := &typedPortForwardChild{
		id:         streamID,
		done:       make(chan struct{}),
		cancel:     func() {},
		recvCredit: recvCredit,
		writeCh:    make(chan struct{}, 1),
	}
	server := &typedPortForwardServer{
		children: map[uint32]*typedPortForwardChild{streamID: child},
	}
	if err := server.halfClose(protocol.Frame{Type: protocol.TypeStreamHalfClose, StreamID: streamID}); err != nil {
		t.Fatal(err)
	}
	if err := server.data(protocol.Frame{Type: protocol.TypeStreamData, StreamID: streamID, Payload: []byte("late")}); err == nil {
		t.Fatal("data after half-close was accepted")
	}
}

type typedPortForwardBlockingCloseConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *typedPortForwardBlockingCloseConn) Close() error {
	c.once.Do(func() {
		close(c.started)
		<-c.release
	})
	return c.Conn.Close()
}

func TestTypedPortForwardChildAcceptanceSerializesParentClosure(t *testing.T) {
	const parentID = protocol.MinTypedStreamID
	const childID = protocol.MinTypedStreamID + 1
	parent := &typedPortForwardParent{id: parentID, children: make(map[uint32]*typedPortForwardChild)}
	acceptedStarted := make(chan struct{})
	releaseAccepted := make(chan struct{})
	var acceptedOnce sync.Once
	var acceptedMu sync.Mutex
	acceptedCount := 0
	server := &typedPortForwardServer{
		parents:  map[uint32]*typedPortForwardParent{parentID: parent},
		children: make(map[uint32]*typedPortForwardChild),
		registry: newTypedParentStreamRegistry(),
		write: func(frame protocol.Frame) error {
			if frame.Type == protocol.TypeStreamAccepted {
				acceptedOnce.Do(func() {
					close(acceptedStarted)
					<-releaseAccepted
				})
				acceptedMu.Lock()
				acceptedCount++
				acceptedMu.Unlock()
			}
			return nil
		},
	}
	if err := server.registry.reserve(childID, protocol.StreamKindPortForwardChild); err != nil {
		t.Fatal(err)
	}
	local, peer := net.Pipe()
	defer peer.Close()
	done := make(chan struct{})
	child := &typedPortForwardChild{
		id: childID, parent: parent, conn: local,
		done: done, cancel: func() { close(done) },
	}
	accepted := make(chan struct {
		ok  bool
		err error
	}, 1)
	go func() {
		ok, err := server.publishChildAcceptance(parent, child)
		accepted <- struct {
			ok  bool
			err error
		}{ok: ok, err: err}
	}()
	select {
	case <-acceptedStarted:
	case <-time.After(time.Second):
		t.Fatal("child acceptance did not reach its publication point")
	}
	if parent.acceptMu.TryLock() {
		parent.acceptMu.Unlock()
		t.Fatal("acceptance publication did not hold the parent gate")
	}
	closed := make(chan struct{})
	go func() {
		server.markParentClosed(parent)
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("parent closure passed an in-flight acceptance publication")
	default:
	}
	close(releaseAccepted)
	result := <-accepted
	if result.err != nil || !result.ok {
		t.Fatalf("child acceptance = %v, %v; want accepted", result.ok, result.err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("parent closure did not finish after acceptance publication")
	}
	if !parent.closed {
		t.Fatal("parent was not marked closed")
	}
	acceptedMu.Lock()
	count := acceptedCount
	acceptedMu.Unlock()
	if count != 1 {
		t.Fatalf("accepted frames = %d, want exactly one", count)
	}

	secondID := childID + 1
	if err := server.registry.reserve(secondID, protocol.StreamKindPortForwardChild); err != nil {
		t.Fatal(err)
	}
	secondLocal, secondPeer := net.Pipe()
	defer secondPeer.Close()
	secondDone := make(chan struct{})
	second := &typedPortForwardChild{
		id: secondID, parent: parent, conn: secondLocal,
		done: secondDone, cancel: func() { close(secondDone) },
	}
	ok, err := server.publishChildAcceptance(parent, second)
	if err != nil || ok {
		t.Fatalf("child accepted after parent closure = %v, %v", ok, err)
	}
	acceptedMu.Lock()
	count = acceptedCount
	acceptedMu.Unlock()
	if count != 1 {
		t.Fatalf("accepted frames after parent closure = %d, want 1", count)
	}
	second.signalClose()
	_ = secondLocal.Close()
	server.detachChild(childID)
	_ = local.Close()
}

func TestTypedPortForwardChildCloseBoundsBlockedConnection(t *testing.T) {
	const parentID = protocol.MinTypedStreamID
	const childID = protocol.MinTypedStreamID + 1
	parent := &typedPortForwardParent{id: parentID, children: make(map[uint32]*typedPortForwardChild)}
	local, peer := net.Pipe()
	defer peer.Close()
	release := make(chan struct{})
	blocked := &typedPortForwardBlockingCloseConn{
		Conn: local, started: make(chan struct{}), release: release,
	}
	done := make(chan struct{})
	child := &typedPortForwardChild{
		id: childID, parent: parent, conn: blocked,
		done: done, cancel: func() { close(done) },
	}
	server := &typedPortForwardServer{
		parents: map[uint32]*typedPortForwardParent{parentID: parent},
		children: map[uint32]*typedPortForwardChild{childID: child},
		registry: newTypedParentStreamRegistry(),
		cleanupTimeout: 25 * time.Millisecond,
	}
	parent.children[childID] = child
	if err := server.registry.reserve(childID, protocol.StreamKindPortForwardChild); err != nil {
		t.Fatal(err)
	}
	if err := server.registry.accept(childID, protocol.StreamKindPortForwardChild); err != nil {
		t.Fatal(err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- server.closeChild(childID, "test", false) }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("child cleanup did not start connection close")
	}
	select {
	case err := <-closeDone:
		if !errors.Is(err, portforward.ErrDestinationCleanupIncomplete) {
			t.Fatalf("child close result = %v, want bounded cleanup error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("child close waited indefinitely for a blocked connection")
	}
	close(release)
	select {
	case <-child.closeDone:
	case <-time.After(time.Second):
		t.Fatal("owned child close worker did not finish after release")
	}
}


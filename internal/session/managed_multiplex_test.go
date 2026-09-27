package session

import (
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func newManagedMuxStateForTest() (*ManagedMultiplexTerminal, *managedMuxChild) {
	child := newManagedMuxChild(protocol.MinTypedStreamID, true)
	s := &ManagedMultiplexTerminal{
		typed:   true,
		streams: map[uint32]*managedMuxChild{protocol.MinTypedStreamID: child},
		done:    make(chan struct{}),
	}
	return s, child
}

func typedAcceptedFrameForTest(t *testing.T, window uint32) protocol.Frame {
	t.Helper()
	payload, err := protocol.JSON(protocol.StreamAccepted{InitialWindow: window})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Frame{Type: protocol.TypeStreamAccepted, StreamID: protocol.MinTypedStreamID, Payload: payload}
}

func TestManagedMultiplexRejectsDuplicateAcceptedWithoutResettingCredit(t *testing.T) {
	s, child := newManagedMuxStateForTest()
	frame := typedAcceptedFrameForTest(t, 64)
	if !s.handleAccepted(frame) {
		t.Fatal("first stream acceptance rejected")
	}
	if err := <-child.accepted; err != nil {
		t.Fatalf("stream acceptance error = %v", err)
	}
	child.mu.Lock()
	child.sendCredit = 0
	child.mu.Unlock()
	if s.handleAccepted(frame) {
		t.Fatal("duplicate stream acceptance accepted")
	}
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.sendCredit != 0 {
		t.Fatalf("duplicate acceptance reset send credit to %d", child.sendCredit)
	}
}

func TestManagedMultiplexRejectsDataAndWindowBeforeAccepted(t *testing.T) {
	s, _ := newManagedMuxStateForTest()
	if s.handleTypedData(protocol.Frame{Type: protocol.TypeStreamData, StreamID: protocol.MinTypedStreamID, Payload: []byte("x")}) {
		t.Fatal("typed data accepted before stream acceptance")
	}
	payload, err := protocol.JSON(protocol.StreamWindowUpdate{Bytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if s.handleWindowUpdate(protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: protocol.MinTypedStreamID, Payload: payload}) {
		t.Fatal("window update accepted before stream acceptance")
	}
}

func TestManagedMultiplexPreAcceptStreamErrorUnblocksOpenWithoutClosingParent(t *testing.T) {
	s, child := newManagedMuxStateForTest()
	payload, err := protocol.JSON(protocol.StreamError{Code: "pty_error", Message: "terminal unavailable"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.handleStreamError(protocol.Frame{Type: protocol.TypeStreamError, StreamID: protocol.MinTypedStreamID, Payload: payload}) {
		t.Fatal("pre-accept stream error rejected")
	}
	if err := <-child.accepted; err == nil {
		t.Fatal("pre-accept stream error did not reject opener")
	}
	select {
	case <-child.done:
	default:
		t.Fatal("rejected child remains open")
	}
	select {
	case <-s.done:
		t.Fatal("stream rejection closed parent session")
	default:
	}
}

func TestManagedMultiplexStreamCloseRequiresAcceptanceAndIsChildScoped(t *testing.T) {
	s, child := newManagedMuxStateForTest()
	payload, err := protocol.JSON(protocol.StreamClose{Reason: "done"})
	if err != nil {
		t.Fatal(err)
	}
	frame := protocol.Frame{Type: protocol.TypeStreamClose, StreamID: protocol.MinTypedStreamID, Payload: payload}
	if s.handleStreamClose(frame) {
		t.Fatal("stream close accepted before stream acceptance")
	}
	child.mu.Lock()
	child.acceptedOK = true
	child.mu.Unlock()
	if !s.handleStreamClose(frame) {
		t.Fatal("accepted stream close rejected")
	}
	select {
	case <-child.done:
	default:
		t.Fatal("closed child remains open")
	}
	select {
	case <-s.done:
		t.Fatal("child close closed parent session")
	default:
	}
}

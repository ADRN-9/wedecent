package session

import (
	"testing"

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

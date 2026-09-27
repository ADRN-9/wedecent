package session

import (
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestSessionAcceptedFramePreservesLegacyEmptyPayload(t *testing.T) {
	frame, err := sessionAcceptedFrame(nil)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != protocol.TypeSessionAccepted {
		t.Fatalf("type = %d", frame.Type)
	}
	if len(frame.Payload) != 0 {
		t.Fatalf("legacy payload = %q", frame.Payload)
	}
}

func TestSessionAcceptedFrameCarriesNegotiatedTypedStreams(t *testing.T) {
	frame, err := sessionAcceptedFrame([]protocol.Capability{protocol.CapabilityTypedStreamsV1})
	if err != nil {
		t.Fatal(err)
	}
	var accepted protocol.SessionAccepted
	if err := protocol.ParseJSON(frame.Payload, &accepted); err != nil {
		t.Fatal(err)
	}
	if len(accepted.Capabilities) != 1 || accepted.Capabilities[0] != protocol.CapabilityTypedStreamsV1 {
		t.Fatalf("capabilities = %#v", accepted.Capabilities)
	}
}

func TestRouteTypedTerminalFrameRequiresNegotiation(t *testing.T) {
	handled, err := routeTypedTerminalFrame(nil, nil, protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2})
	if !handled {
		t.Fatal("typed frame was not classified")
	}
	if !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("error = %v", err)
	}
}

func TestRouteTypedTerminalFrameRequiresServerAfterNegotiation(t *testing.T) {
	handled, err := routeTypedTerminalFrame(
		[]protocol.Capability{protocol.CapabilityTypedStreamsV1},
		nil,
		protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2},
	)
	if !handled {
		t.Fatal("typed frame was not classified")
	}
	if !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("error = %v", err)
	}
}

func TestRouteTypedTerminalFrameLeavesLegacyFramesAlone(t *testing.T) {
	handled, err := routeTypedTerminalFrame(nil, nil, protocol.Frame{Type: protocol.TypeData, StreamID: terminalStreamID})
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Fatal("legacy frame was classified as typed")
	}
}

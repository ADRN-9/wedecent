package session

import (
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestSessionAcceptedPayloadPreservesLegacyEmptyEncoding(t *testing.T) {
	if payload := sessionAcceptedPayload(nil); len(payload) != 0 {
		t.Fatalf("legacy accepted payload = %q", payload)
	}
	payload := sessionAcceptedPayload([]protocol.Capability{protocol.CapabilityTypedStreamsV1})
	var accepted protocol.SessionAccepted
	if err := protocol.ParseJSON(payload, &accepted); err != nil {
		t.Fatal(err)
	}
	if len(accepted.Capabilities) != 1 || accepted.Capabilities[0] != protocol.CapabilityTypedStreamsV1 {
		t.Fatalf("accepted capabilities = %#v", accepted.Capabilities)
	}
}

func TestRouteNegotiatedTypedTerminalFrameRejectsUnnegotiatedTraffic(t *testing.T) {
	frame := protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: protocol.MinTypedStreamID}
	handled, err := routeNegotiatedTypedTerminalFrame(nil, nil, frame)
	if !handled || !errors.Is(err, errTypedStreamsNotNegotiated) {
		t.Fatalf("route = handled %v error %v", handled, err)
	}
}

func TestRouteNegotiatedTypedTerminalFrameLeavesLegacyTrafficAlone(t *testing.T) {
	handled, err := routeNegotiatedTypedTerminalFrame(
		[]protocol.Capability{protocol.CapabilityTypedStreamsV1},
		nil,
		protocol.Frame{Type: protocol.TypePing},
	)
	if handled || err != nil {
		t.Fatalf("legacy route = handled %v error %v", handled, err)
	}
}

func TestTypedTerminalFrameClassifierIncludesAllTypedFrames(t *testing.T) {
	for _, frameType := range []protocol.Type{
		protocol.TypeStreamOpen,
		protocol.TypeStreamAccepted,
		protocol.TypeStreamData,
		protocol.TypeStreamWindowUpdate,
		protocol.TypeStreamResize,
		protocol.TypeStreamClose,
		protocol.TypeStreamError,
	} {
		if !isTypedTerminalFrameType(frameType) {
			t.Fatalf("typed frame %d not classified", frameType)
		}
	}
	if isTypedTerminalFrameType(protocol.TypeData) {
		t.Fatal("legacy data classified as typed")
	}
}

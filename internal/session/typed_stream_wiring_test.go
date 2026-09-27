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

func TestRouteTypedTerminalFrameAcknowledgesPeerClose(t *testing.T) {
	sink := &typedFrameSink{}
	server := newTypedTerminalServerWithStarter(
		"/bin/sh",
		sink.write,
		func(string, uint16, uint16, string) (typedTerminalPTY, error) { return newFakeTypedPTY(), nil },
	)
	capabilities := []protocol.Capability{protocol.CapabilityTypedStreamsV1}

	handled, err := routeTypedTerminalFrame(capabilities, server, protocol.Frame{
		Type:     protocol.TypeStreamOpen,
		StreamID: protocol.MinTypedStreamID,
		Payload:  typedOpenPayload(t, 64<<10),
	})
	if err != nil || !handled {
		t.Fatalf("open handled=%v err=%v", handled, err)
	}

	closePayload, err := protocol.JSON(protocol.StreamClose{Reason: "client_close"})
	if err != nil {
		t.Fatal(err)
	}
	handled, err = routeTypedTerminalFrame(capabilities, server, protocol.Frame{
		Type:     protocol.TypeStreamClose,
		StreamID: protocol.MinTypedStreamID,
		Payload:  closePayload,
	})
	if err != nil || !handled {
		t.Fatalf("close handled=%v err=%v", handled, err)
	}

	frames := sink.snapshot()
	if len(frames) != 2 || frames[0].Type != protocol.TypeStreamAccepted || frames[1].Type != protocol.TypeStreamClose {
		t.Fatalf("frames = %#v", frames)
	}
	if frames[1].StreamID != protocol.MinTypedStreamID {
		t.Fatalf("close ack stream id = %d", frames[1].StreamID)
	}
	var ack protocol.StreamClose
	if err := protocol.ParseTypedStreamJSON(frames[1].Payload, &ack); err != nil {
		t.Fatal(err)
	}
	if err := protocol.ValidateStreamClose(frames[1].StreamID, ack); err != nil {
		t.Fatalf("close ack = %#v err=%v", ack, err)
	}
}

package session

import (
	"fmt"

	"wedecent.com/wedecent/internal/protocol"
)

func sessionAcceptedFrame(capabilities []protocol.Capability) (protocol.Frame, error) {
	frame := protocol.Frame{Type: protocol.TypeSessionAccepted}
	if len(capabilities) == 0 {
		return frame, nil
	}
	payload, err := protocol.JSON(protocol.SessionAccepted{Capabilities: capabilities})
	if err != nil {
		return protocol.Frame{}, err
	}
	frame.Payload = payload
	return frame, nil
}

func routeTypedTerminalFrame(capabilities []protocol.Capability, server *typedTerminalServer, frame protocol.Frame) (bool, error) {
	if !isTypedTerminalFrame(frame.Type) {
		return false, nil
	}
	if !hasSessionCapability(capabilities, protocol.CapabilityTypedStreamsV1) {
		return true, fmt.Errorf("%w: typed stream frame received without negotiation", errTypedStreamProtocol)
	}
	if server == nil {
		return true, fmt.Errorf("%w: typed terminal server unavailable", errTypedStreamProtocol)
	}
	if err := server.Handle(frame); err != nil {
		return true, err
	}
	if frame.Type != protocol.TypeStreamClose {
		return true, nil
	}

	ack := protocol.StreamClose{Reason: "peer_close"}
	if err := protocol.ValidateStreamClose(frame.StreamID, ack); err != nil {
		return true, fmt.Errorf("%w: invalid stream close acknowledgement: %v", errTypedStreamProtocol, err)
	}
	payload, err := protocol.JSON(ack)
	if err != nil {
		return true, err
	}
	if err := server.writeFrame(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: frame.StreamID, Payload: payload}); err != nil {
		return true, err
	}
	return true, nil
}

func isTypedTerminalFrame(frameType protocol.Type) bool {
	switch frameType {
	case protocol.TypeStreamOpen,
		protocol.TypeStreamAccepted,
		protocol.TypeStreamData,
		protocol.TypeStreamWindowUpdate,
		protocol.TypeStreamResize,
		protocol.TypeStreamClose,
		protocol.TypeStreamError:
		return true
	default:
		return false
	}
}

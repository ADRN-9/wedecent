package session

import (
	"errors"

	"wedecent.com/wedecent/internal/protocol"
)

var errTypedStreamsNotNegotiated = errors.New("typed terminal streams were not negotiated")

func sessionAcceptedPayload(capabilities []protocol.Capability) []byte {
	if len(capabilities) == 0 {
		return nil
	}
	return mustJSON(protocol.SessionAccepted{Capabilities: capabilities})
}

func isTypedTerminalFrameType(frameType protocol.Type) bool {
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

func routeNegotiatedTypedTerminalFrame(capabilities []protocol.Capability, server *typedTerminalServer, frame protocol.Frame) (bool, error) {
	if !isTypedTerminalFrameType(frame.Type) {
		return false, nil
	}
	if !hasSessionCapability(capabilities, protocol.CapabilityTypedStreamsV1) || server == nil {
		return true, errTypedStreamsNotNegotiated
	}
	return true, server.Handle(frame)
}

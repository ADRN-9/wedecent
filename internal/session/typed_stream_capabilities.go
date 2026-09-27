package session

import "wedecent.com/wedecent/internal/protocol"

// negotiateSessionCapabilities preserves the existing terminal-only live-server
// call boundary. File transfer is not advertised through this wrapper.
func negotiateSessionCapabilities(requested []protocol.Capability, typedStreamsReady bool) []protocol.Capability {
	return negotiateSessionCapabilitiesForRuntime(requested, typedStreamsReady, false)
}

func negotiateSessionCapabilitiesForRuntime(requested []protocol.Capability, typedStreamsReady, fileTransferReady bool) []protocol.Capability {
	if !typedStreamsReady {
		return nil
	}
	requestedTyped := false
	requestedFile := false
	for _, capability := range requested {
		switch capability {
		case protocol.CapabilityTypedStreamsV1:
			requestedTyped = true
		case protocol.CapabilityFileTransferV1:
			requestedFile = true
		}
	}
	if !requestedTyped || !protocol.SupportedCapability(protocol.CapabilityTypedStreamsV1) {
		return nil
	}
	negotiated := []protocol.Capability{protocol.CapabilityTypedStreamsV1}
	if fileTransferReady && requestedFile && protocol.SupportedCapability(protocol.CapabilityFileTransferV1) {
		negotiated = append(negotiated, protocol.CapabilityFileTransferV1)
	}
	return negotiated
}

func hasSessionCapability(capabilities []protocol.Capability, want protocol.Capability) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}

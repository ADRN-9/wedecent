package session

import "wedecent.com/wedecent/internal/protocol"

func negotiateSessionCapabilities(requested []protocol.Capability, typedStreamsReady bool) []protocol.Capability {
	if !typedStreamsReady {
		return nil
	}
	for _, capability := range requested {
		if capability == protocol.CapabilityTypedStreamsV1 && protocol.SupportedCapability(capability) {
			return []protocol.Capability{protocol.CapabilityTypedStreamsV1}
		}
	}
	return nil
}

func hasSessionCapability(capabilities []protocol.Capability, want protocol.Capability) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}

package protocol

// Capability identifies an explicitly negotiated optional application-session
// behavior. Capability strings are protocol constants, never renderer-provided
// free-form operation names.
type Capability string

const (
	CapabilityTypedStreamsV1 Capability = "typed-streams-v1"
	CapabilityFileTransferV1 Capability = "file-transfer-v1"
)

func SupportedCapability(value Capability) bool {
	switch value {
	case CapabilityTypedStreamsV1, CapabilityFileTransferV1:
		return true
	default:
		return false
	}
}

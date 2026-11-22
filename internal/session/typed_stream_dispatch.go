package session

import (
	"context"
	"errors"
	"fmt"

	"wedecent.com/wedecent/internal/protocol"
)

// routeTypedApplicationFrame dispatches an already-authenticated parent's typed
// child frame by the operation kind recorded in the parent StreamID registry.
// It does not authorize file access itself; the file engine performs separate
// per-operation authorization before touching rooted storage.
func routeTypedApplicationFrame(
	ctx context.Context,
	capabilities []protocol.Capability,
	registry *typedParentStreamRegistry,
	terminalServer *typedTerminalServer,
	fileServer *typedFileServer,
	frame protocol.Frame,
) (bool, error) {
	if !isTypedTerminalFrame(frame.Type) {
		return false, nil
	}
	if !hasSessionCapability(capabilities, protocol.CapabilityTypedStreamsV1) {
		return true, fmt.Errorf("%w: typed stream frame received without negotiation", errTypedStreamProtocol)
	}
	if registry == nil {
		return true, fmt.Errorf("%w: typed stream registry unavailable", errTypedStreamProtocol)
	}

	if frame.Type == protocol.TypeStreamOpen {
		var open protocol.StreamOpen
		if err := protocol.ParseTypedStreamJSON(frame.Payload, &open); err != nil {
			return true, fmt.Errorf("%w: malformed typed stream open", errTypedStreamProtocol)
		}
		switch open.Kind {
		case protocol.StreamKindTerminal:
			return routeTypedTerminalFrame(capabilities, terminalServer, frame)
		case protocol.StreamKindFileUpload, protocol.StreamKindFileDownload:
			if !hasSessionCapability(capabilities, protocol.CapabilityFileTransferV1) {
				return true, fmt.Errorf("%w: file stream received without negotiation", errTypedStreamProtocol)
			}
			if fileServer == nil {
				return true, fmt.Errorf("%w: typed file server unavailable", errTypedStreamProtocol)
			}
			return true, fileServer.Handle(ctx, frame)
		default:
			return true, fmt.Errorf("%w: unsupported typed stream kind", errTypedStreamProtocol)
		}
	}

	kind, ok := registry.kind(frame.StreamID)
	if !ok {
		return true, fmt.Errorf("%w: typed stream %d is not open", errTypedStreamProtocol, frame.StreamID)
	}
	switch kind {
	case protocol.StreamKindTerminal:
		return routeTypedTerminalFrame(capabilities, terminalServer, frame)
	case protocol.StreamKindFileUpload, protocol.StreamKindFileDownload:
		if !hasSessionCapability(capabilities, protocol.CapabilityFileTransferV1) {
			return true, fmt.Errorf("%w: file stream received without negotiation", errTypedStreamProtocol)
		}
		if fileServer == nil {
			return true, fmt.Errorf("%w: typed file server unavailable", errTypedStreamProtocol)
		}
		return true, fileServer.Handle(ctx, frame)
	default:
		return true, fmt.Errorf("%w: unsupported typed stream kind", errTypedStreamProtocol)
	}
}

var errTypedSessionTerminated = errors.New("typed terminal parent session is terminated")

// dispatchTypedSessionFrame drops frames that were already buffered when
// revocation won. The terminal server's closed reservation gate separately
// handles a termination that races after this check.
func dispatchTypedSessionFrame(
	active *activeTerminalSession,
	closeReason *typedSessionCloseReason,
	ctx context.Context,
	capabilities []protocol.Capability,
	registry *typedParentStreamRegistry,
	terminalServer *typedTerminalServer,
	fileServer *typedFileServer,
	frame protocol.Frame,
) (bool, error) {
	if active != nil && active.isTerminated() {
		closeReason.set(active.reasonOr("client_revoked"))
		return true, errTypedSessionTerminated
	}
	return routeTypedApplicationFrame(ctx, capabilities, registry, terminalServer, fileServer, frame)
}

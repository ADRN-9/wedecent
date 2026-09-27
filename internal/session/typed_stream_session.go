package session

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/protocol"
)

func (s *Server) handleTypedTerminalSession(conn *tls.Conn, peerID, peerName, transport string, capabilities []protocol.Capability) {
	fileNegotiated := hasSessionCapability(capabilities, protocol.CapabilityFileTransferV1)
	if fileNegotiated && (s.FileTransfer == nil || !s.FileTransfer.Ready()) {
		// Capability negotiation must never outrun the authoritative runtime.
		return
	}
	accepted, err := sessionAcceptedFrame(capabilities)
	if err != nil {
		return
	}

	var writeMu sync.Mutex
	writeFrame := func(frame protocol.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteFrame(conn, frame)
	}
	if err := writeFrame(accepted); err != nil {
		return
	}

	s.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "success", PeerID: peerID, Transport: transport})
	closeReason := "connection_ended"
	defer func() {
		s.recordAudit(audit.Event{Type: "terminal.session_closed", Outcome: "success", PeerID: peerID, Transport: transport, Reason: closeReason})
	}()
	s.log().Info("typed terminal session opened", "client_id", peerID, "client_name", peerName)

	policyTimers := newSessionPolicyTimers(s.Policy)
	defer policyTimers.Stop()
	activityCh := make(chan struct{}, 1)
	signalActivity := func() {
		select {
		case activityCh <- struct{}{}:
		default:
		}
	}

	sessionCtx, cancelSession := context.WithCancel(context.Background())
	defer cancelSession()
	registry := newTypedParentStreamRegistry()
	streamAudit := newTypedTerminalAuditTracker(peerID, transport, s.recordAudit)
	typedServer := newTypedTerminalServerWithRegistry(s.Shell, func(frame protocol.Frame) error {
		if err := writeFrame(frame); err != nil {
			return err
		}
		streamAudit.observeOutgoing(frame)
		signalActivity()
		return nil
	}, registry)
	var fileServer *typedFileServer
	if fileNegotiated {
		fileServer = newTypedFileServer(s.FileTransfer, peerID, registry, func(frame protocol.Frame) error {
			if err := writeFrame(frame); err != nil {
				return err
			}
			signalActivity()
			return nil
		})
	}
	defer func() {
		cancelSession()
		if fileServer != nil {
			fileServer.CloseAll()
		}
		typedServer.CloseAll()
		streamAudit.closeAll(closeReason)
	}()

	done := make(chan struct{})
	defer close(done)
	frameCh := make(chan protocol.Frame, 1)
	readErrCh := make(chan error, 1)
	go func() {
		for {
			frame, err := protocol.ReadFrame(conn)
			if err != nil {
				select {
				case readErrCh <- err:
				case <-done:
				}
				return
			}
			select {
			case frameCh <- frame:
			case <-done:
				return
			}
		}
	}()

	expireSession := func(reason string) {
		cancelSession()
		if fileServer != nil {
			fileServer.CloseAll()
		}
		typedServer.CloseAll()
		streamAudit.closeAll(closeReason)
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = writeFrame(protocol.Frame{Type: protocol.TypeClose, Payload: mustJSON(protocol.Close{ExitCode: sessionPolicyExitCode, Reason: reason})})
		waitForPeerClose(frameCh, readErrCh, 2*time.Second)
	}

	for {
		select {
		case err := <-readErrCh:
			closeReason = "peer_disconnect"
			if !errors.Is(err, io.EOF) {
				s.log().Debug("typed session read ended", "error", err)
			}
			return
		case frame := <-frameCh:
			handled, err := routeTypedApplicationFrame(sessionCtx, capabilities, registry, typedServer, fileServer, frame)
			if handled {
				if err != nil {
					closeReason = "typed_stream_protocol_error"
					_ = writeFrame(protocol.Frame{Type: protocol.TypeError, Payload: mustJSON(protocol.Error{Code: "protocol_error", Message: "invalid typed stream operation"})})
					return
				}
				streamAudit.observeIncoming(frame)
				policyTimers.Activity()
				continue
			}
			switch frame.Type {
			case protocol.TypePing:
				if err := writeFrame(protocol.Frame{Type: protocol.TypePong}); err != nil {
					closeReason = "transport_write_failed"
					return
				}
			case protocol.TypeClose:
				closeReason = "peer_close"
				return
			default:
				closeReason = "unexpected_message"
				_ = writeFrame(protocol.Frame{Type: protocol.TypeError, Payload: mustJSON(protocol.Error{Code: "unexpected_message", Message: "unexpected frame in typed terminal session"})})
				return
			}
		case <-activityCh:
			policyTimers.Activity()
		case <-policyTimers.idleC:
			closeReason = "policy_idle_timeout"
			expireSession("session idle timeout")
			return
		case <-policyTimers.maxC:
			closeReason = "policy_max_duration"
			expireSession("session maximum duration reached")
			return
		}
	}
}

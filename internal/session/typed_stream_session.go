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

func (s *Server) handleTypedTerminalSession(conn *tls.Conn, peerID, peerName string, metadata TransportMetadata, capabilities []protocol.Capability, buildIdentity *protocol.AgentBuildIdentity, authorization *GrantConsumptionEvidence, active *activeTerminalSession) {
	transport, _ := metadata.auditLabel()
	fileNegotiated := hasSessionCapability(capabilities, protocol.CapabilityFileTransferV1)
	if active == nil {
		return
	}
	closeReason := newTypedSessionCloseReason("connection_ended")
	sessionOpened := false
	defer func() {
		finishErr := active.finish()
		finalCloseReason := resolveTypedSessionCloseReason(active, closeReason)
		if !sessionOpened {
			if finishErr != nil {
				s.log().Error("typed terminal session cleanup failed before acceptance",
					"client_id", peerID, "session_id", active.ID, "error", finishErr)
			}
			return
		}
		outcome := "success"
		if finishErr != nil {
			outcome = "failed"
			s.log().Error("typed terminal session cleanup failed",
				"client_id", peerID, "session_id", active.ID, "error", finishErr)
		}
		if err := s.recordGrantAudit(metadata, audit.Event{
			Type: "terminal.session_closed", Outcome: outcome, PeerID: peerID,
			SessionID: active.ID, Transport: transport, Reason: finalCloseReason,
		}, authorization); err != nil {
			s.log().Error("typed terminal session close audit failed",
				"client_id", peerID, "session_id", active.ID, "error", err)
		}
	}()
	if fileNegotiated && (s.FileTransfer == nil || !s.FileTransfer.Ready()) {
		// Capability negotiation must never outrun the authoritative runtime.
		closeReason.set("file_transfer_runtime_unavailable")
		_ = abortSessionTransport(active.rawConn)
		return
	}

	var writeMu sync.Mutex
	writeFrame := func(frame protocol.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteFrame(conn, frame)
	}
	if err := s.recordGrantAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "success", PeerID: peerID, SessionID: active.ID, Transport: transport}, authorization); err != nil {
		closeReason.set("session_open_audit_failed")
		s.log().Error("typed terminal session open audit failed",
			"client_id", peerID, "session_id", active.ID, "error", err)
		_ = abortSessionTransport(active.rawConn)
		return
	}
	sessionOpened = true
	s.log().Info("typed terminal session opened", "client_id", peerID, "client_name", peerName)
	if active.isTerminated() {
		closeReason.set(active.reasonOr("client_revoked"))
		return
	}

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
	registry := newTypedParentStreamRegistry()
	streamAudit := newTypedTerminalAuditTracker(peerID, transport, func(event audit.Event) {
		s.recordGrantAudit(metadata, event, authorization)
	}, active.ID)
	typedServer := newTypedTerminalServerWithStarterAndRegistry(s.Shell, func(frame protocol.Frame) error {
		if err := writeFrame(frame); err != nil {
			return err
		}
		streamAudit.observeOutgoing(frame)
		signalActivity()
		return nil
	}, func(shell string, cols, rows uint16, term string) (typedTerminalPTY, error) {
		return s.startTerminal(shell, cols, rows, term)
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
	var resourceCleanupOnce sync.Once
	var resourceCleanupErr error
	closeResources := func() error {
		resourceCleanupOnce.Do(func() {
			cancelSession()
			var closeErrors []error
			if fileServer != nil {
				if err := fileServer.CloseAll(); err != nil {
					closeErrors = append(closeErrors, err)
				}
			}
			if err := typedServer.CloseAll(); err != nil {
				closeErrors = append(closeErrors, err)
			}
			streamAudit.closeAll(resolveTypedSessionCloseReason(active, closeReason))
			resourceCleanupErr = errors.Join(closeErrors...)
		})
		return resourceCleanupErr
	}
	if err := active.setCleanup(closeResources); err != nil {
		closeReason.set("session_cleanup_registration_failed")
		if cleanupErr := closeResources(); cleanupErr != nil {
			s.log().Error("typed terminal session cleanup registration failed",
				"client_id", peerID, "session_id", active.ID, "error", errors.Join(err, cleanupErr))
		}
		return
	}

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
		if err := closeResources(); err != nil {
			closeReason.set("session_cleanup_failed")
			s.log().Error("typed terminal session cleanup failed during policy expiration",
				"client_id", peerID, "session_id", active.ID, "error", err)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = writeFrame(protocol.Frame{Type: protocol.TypeClose, Payload: mustJSON(protocol.Close{ExitCode: sessionPolicyExitCode, Reason: reason})})
		waitForPeerClose(frameCh, readErrCh, 2*time.Second)
	}

	for {
		select {
		case err := <-readErrCh:
			closeReason.set(active.reasonOr("peer_disconnect"))
			if !errors.Is(err, io.EOF) {
				s.log().Debug("typed session read ended", "error", err)
			}
			return
		case frame := <-frameCh:
			handled, err := routeTypedApplicationFrame(sessionCtx, capabilities, registry, typedServer, fileServer, frame)
			if handled {
				if err != nil {
					closeReason.set("typed_stream_protocol_error")
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
					closeReason.set("transport_write_failed")
					return
				}
			case protocol.TypeClose:
				closeReason.set("peer_close")
				return
			default:
				closeReason.set("unexpected_message")
				_ = writeFrame(protocol.Frame{Type: protocol.TypeError, Payload: mustJSON(protocol.Error{Code: "unexpected_message", Message: "unexpected frame in typed terminal session"})})
				return
			}
		case <-activityCh:
			policyTimers.Activity()
		case <-policyTimers.idleC:
			closeReason.set("policy_idle_timeout")
			expireSession("session idle timeout")
			return
		case <-policyTimers.maxC:
			closeReason.set("policy_max_duration")
			expireSession("session maximum duration reached")
			return
		}
	}
}

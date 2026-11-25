package session

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/protocol"
)

func (s *Server) handleTypedTerminalSession(conn *tls.Conn, peerID, peerName, transport string, capabilities []protocol.Capability, routerIDs ...string) {
	fileNegotiated := hasSessionCapability(capabilities, protocol.CapabilityFileTransferV1)
	forwardNegotiated := hasSessionCapability(capabilities, protocol.CapabilityPortForwardV1)
	if forwardNegotiated && (s.PortForwarding == nil || !s.PortForwarding.Ready()) {
		return
	}
	if fileNegotiated && (s.FileTransfer == nil || !s.FileTransfer.Ready()) {
		// Capability negotiation must never outrun the authoritative runtime.
		return
	}
	accepted, err := sessionAcceptedFrame(capabilities)
	if err != nil {
		return
	}

	sessionCtx, cancelSession := context.WithCancel(context.Background())
	defer cancelSession()
	writeLock := make(chan struct{}, 1)
	writeFrameWithContext := func(ctx context.Context, frame protocol.Frame) error {
		if ctx == nil {
			ctx = context.Background()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case writeLock <- struct{}{}:
		}
		defer func() { <-writeLock }()
		if err := ctx.Err(); err != nil {
			return err
		}
		deadline := time.Now().Add(2 * time.Second)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			cancelSession()
			_ = abortTLSConn(conn)
			return err
		}
		writeErr := protocol.WriteFrame(conn, frame)
		resetErr := conn.SetWriteDeadline(time.Time{})
		if err := errors.Join(writeErr, resetErr); err != nil {
			cancelSession()
			_ = abortTLSConn(conn)
			return err
		}
		return nil
	}
	writeFrame := func(frame protocol.Frame) error {
		return writeFrameWithContext(sessionCtx, frame)
	}
	if err := writeFrameWithContext(context.Background(), accepted); err != nil {
		cancelSession()
		_ = abortTLSConn(conn)
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
	routerID := ""
	if len(routerIDs) > 0 {
		routerID = routerIDs[0]
	}
	var forwardServer *typedPortForwardServer
	if forwardNegotiated {
		forwardServer = newTypedPortForwardServer(sessionCtx, s.Identity.ID, peerID, routerID, s.PortForwarding, registry, func(frame protocol.Frame) error {
			if err := writeFrame(frame); err != nil {
				return err
			}
			signalActivity()
			return nil
		})
	}
	defer func() {
		cancelSession()
		_ = abortTLSConn(conn)
		var cleanupErrs []error
		if forwardServer != nil {
			if err := forwardServer.CloseAll(); err != nil {
				cleanupErrs = append(cleanupErrs, err)
			}
		}
		if fileServer != nil {
			fileServer.CloseAll()
		}
		typedServer.CloseAll()
		streamAudit.closeAll(closeReason)
		if len(cleanupErrs) > 0 {
			s.log().Error("typed forwarding cleanup failed", "peer_id", peerID, "error", errors.Join(cleanupErrs...))
		}
	}()

	done := make(chan struct{})
	defer close(done)
	frameCh := make(chan protocol.Frame, 1)
	readErrCh := make(chan error, 1)
	go func() {
		for {
			frame, err := protocol.ReadFrame(conn)
			if err != nil {
				cancelSession()
				_ = abortTLSConn(conn)
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
		if forwardServer != nil {
			if err := forwardServer.CloseAll(); err != nil {
				s.log().Warn("typed forwarding policy cleanup failed", "peer_id", peerID, "error", err)
			}
		}
		if fileServer != nil {
			fileServer.CloseAll()
		}
		typedServer.CloseAll()
		streamAudit.closeAll(closeReason)
		writeCtx, cancelWrite := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelWrite()
		if err := writeFrameWithContext(writeCtx, protocol.Frame{Type: protocol.TypeClose, Payload: mustJSON(protocol.Close{ExitCode: sessionPolicyExitCode, Reason: reason})}); err != nil {
			s.log().Warn("typed session close frame failed", "peer_id", peerID, "error", err)
			_ = abortTLSConn(conn)
			return
		}
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
			handled, err := routeTypedApplicationFrame(sessionCtx, capabilities, registry, typedServer, fileServer, frame, forwardServer)
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

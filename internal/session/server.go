package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/terminal"
	"wedecent.com/wedecent/internal/trust"
)

const (
	terminalStreamID         = 1
	sessionPolicyExitCode    = 124
	terminalExitDrainTimeout = 2 * time.Second
)

var errTerminalDrainTimeout = errors.New("terminal output drain timeout")

type DirectAuthorizer interface {
	Authorize(context.Context, string, string, string) error
}

type Server struct {
	Identity               *identity.Identity
	Trust                  *trust.Store
	StateDir               string
	Shell                  string
	Logger                 *slog.Logger
	DirectAuthorizer       DirectAuthorizer
	RecoveryAuthority      audit.RecoveryAuthority
	RecoveryAuthorityTrust audit.RecoveryAuthorityTrust
	RecoveryAuthorityScope string
	LegacyPairingRecoveryForTests bool
	FileTransfer           *FileTransferRuntime
	PortForwarding         *PortForwardRuntime
	pairingCompletionAudit func(*audit.Log, audit.Event) error
	Policy                 SessionPolicy
}

func (s *Server) ServeConn(raw net.Conn) {
	s.serveConn(raw, 15*time.Second, true)
}

// ServeParkedRelayConn serves a relay connection that may sit idle until a
// client is matched by the relay. The outer authenticated WebSocket relay is
// responsible for parking the connection; the inner TLS handshake starts only
// when a client arrives, so there is intentionally no pre-client deadline.
func (s *Server) ServeParkedRelayConn(raw net.Conn) {
	s.serveConn(raw, 0, false)
}

func (s *Server) serveConn(raw net.Conn, handshakeTimeout time.Duration, requireInBandAuthorization bool) {
	defer raw.Close()
	transport := "relay"
	if requireInBandAuthorization {
		transport = "direct"
	}
	routerID := ""
	if authenticated, ok := raw.(interface{ AuthenticatedRouterID() string }); ok {
		routerID = authenticated.AuthenticatedRouterID()
	}
	tlsConn := tls.Server(raw, identity.ServerTLS(s.Identity))
	if handshakeTimeout > 0 {
		if err := tlsConn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
			s.log().Warn("TLS handshake deadline could not be set", "remote", raw.RemoteAddr(), "error", err)
			return
		}
	}
	if err := tlsConn.Handshake(); err != nil {
		s.log().Warn("TLS handshake failed", "remote", raw.RemoteAddr(), "error", err)
		return
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		s.log().Warn("TLS handshake deadline could not be cleared", "remote", raw.RemoteAddr(), "error", err)
		return
	}
	first, err := protocol.ReadFrame(tlsConn)
	if err != nil {
		return
	}
	switch first.Type {
	case protocol.TypePairRequest:
		s.handlePair(tlsConn, first, transport)
	case protocol.TypeOpenSession:
		if requireInBandAuthorization {
			s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", Transport: transport, Reason: "authorization_required"})
			_ = sendError(tlsConn, "authorization_required", "this transport requires an authorized session request")
			return
		}
		s.handleTerminal(tlsConn, first, transport)
	case protocol.TypeOpenAuthorizedSession:
		if !requireInBandAuthorization {
			s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", Transport: transport, Reason: "unexpected_authorized_request"})
			_ = sendError(tlsConn, "unexpected_message", "authorized session requests are not valid on this transport")
			return
		}
		s.handleAuthorizedTerminalWithRouter(tlsConn, first, transport, routerID)
	default:
		_ = sendError(tlsConn, "unexpected_message", "expected pairing or session request")
	}
}

func (s *Server) handlePair(conn *tls.Conn, first protocol.Frame, transport string) {
	peer, err := identity.PeerCertificate(conn.ConnectionState())
	if err != nil {
		s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "denied", Transport: transport, Reason: "client_certificate_required"})
		_ = sendError(conn, "client_certificate_required", err.Error())
		return
	}
	var req protocol.PairRequest
	if err := protocol.ParseJSON(first.Payload, &req); err != nil {
		s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "denied", Transport: transport, Reason: "invalid_request"})
		_ = sendError(conn, "bad_request", "invalid pair request")
		return
	}
	fp, err := identity.FingerprintPublicKey(peer.PublicKey)
	if err != nil {
		s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "denied", PeerID: req.ClientID, Transport: transport, Reason: "invalid_client_key"})
		_ = sendError(conn, "pairing_denied", "invalid client key")
		return
	}
	clientID := identity.CertificateDeviceID(peer)
	if clientID == "" || req.ClientID != clientID {
		s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "denied", PeerID: req.ClientID, Transport: transport, Reason: "client_identity_mismatch"})
		_ = sendError(conn, "pairing_denied", "client identity mismatch")
		return
	}
	name := cleanName(req.ClientName)
	if name == "" {
		name = peer.Subject.CommonName
	}
	// Reject invalid secrets before reserving bounded recovery capacity.
	// Locked consumption still checks again, including concurrent rotation.
	valid, err := trust.CheckPairingSecret(s.StateDir, req.PairingSecret)
	if err != nil {
		s.log().Error("pairing state preflight failed", "peer_id", clientID, "error", err)
		_ = sendError(conn, "server_error", "pairing state unavailable")
		return
	}
	if !valid {
		s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_pairing_secret"})
		_ = sendError(conn, "pairing_denied", "invalid or already consumed pairing secret")
		return
	}
	attemptID, err := audit.NewPairingAttemptID()
	if err != nil {
		_ = sendError(conn, "server_error", "pairing audit is unavailable")
		return
	}
	var recovery *audit.PairingRecovery
	if s.RecoveryAuthority != nil && s.RecoveryAuthorityScope != "" {
		recovery, err = audit.OpenPairingRecoveryWithAuthority(s.StateDir, s.RecoveryAuthorityScope, s.RecoveryAuthority, s.RecoveryAuthorityTrust)
	} else if s.LegacyPairingRecoveryForTests {
		// Explicit test-only compatibility; production never treats local HMAC as independent authority.
		recovery, err = audit.OpenPairingRecovery(s.StateDir)
	} else {
		err = audit.ErrRecoveryAuthorityUnavailable
	}
	if err != nil {
		s.log().Error("independent pairing recovery authority unavailable", "peer_id", clientID, "error", err)
		_ = sendError(conn, "recovery_authority_unavailable", "independent pairing recovery authority is unavailable")
		return
	}
	pairingAudit, err := audit.Open(s.StateDir)
	if err != nil {
		s.log().Error("pairing audit unavailable", "peer_id", clientID, "error", err)
		_ = sendError(conn, "server_error", "pairing audit is unavailable")
		return
	}
	admitted, auditReady := false, false
	pairErr := trust.PairClientWithSecretAdmission(s.StateDir, req.PairingSecret, s.Trust, trust.Peer{
		ID: clientID, Name: name, Fingerprint: fp,
	}, func(generation uint64) error {
		reserved, reserveErr := recovery.Reserve(audit.PairingOutcome{
			AttemptID: attemptID, ActorID: s.Identity.ID, PeerID: clientID,
			Fingerprint: fp, CredentialGeneration: generation,
		})
		if reserveErr != nil {
			return reserveErr
		}
		admitted = true
		attemptID = reserved.AttemptID
		if appendErr := pairingAudit.Append(audit.Event{
			Type: "pairing.request", Outcome: "pending", ActorID: s.Identity.ID,
			PeerID: clientID, Transport: transport, AttemptID: attemptID,
		}); appendErr != nil {
			return appendErr
		}
		auditReady = true
		return nil
	})
	if !admitted {
		if errors.Is(pairErr, trust.ErrPairingSecretInvalid) {
			s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_pairing_secret"})
			_ = sendError(conn, "pairing_denied", "invalid, expired, or already consumed pairing secret")
			return
		}
		s.log().Error("pairing generation admission failed", "peer_id", clientID, "error", pairErr)
		_ = sendError(conn, "server_error", "pairing generation is reserved or recovery is unavailable")
		return
	}
	if !auditReady {
		// The durable generation reservation remains pending for exact retry.
		s.log().Error("pairing pending audit could not be synchronized", "peer_id", clientID, "attempt_id", attemptID, "error", pairErr)
		_ = sendError(conn, "server_error", "pairing audit is unavailable; retry the same pairing operation")
		return
	}
	s.handlePairCommit(conn, transport, clientID, name, fp, attemptID, pairingAudit, recovery, pairErr)
}

// handlePairCommit runs only after both independent pending records are durable.
func (s *Server) handlePairCommit(conn *tls.Conn, transport, clientID, name, fp, attemptID string, pairingAudit *audit.Log, recovery *audit.PairingRecovery, pairErr error) {
	reconciled := trust.IsPairingReconciled(pairErr)
	outcome := audit.PairingOutcomeSuccess
	if pairErr != nil && !reconciled {
		outcome = audit.PairingOutcomeFailed
		if errors.Is(pairErr, trust.ErrPairingTrustUncertain) {
			outcome = audit.PairingOutcomeUncertain
		} else if errors.Is(pairErr, trust.ErrPairingSecretInvalid) {
			outcome = audit.PairingOutcomeDenied
		}
	}
	if err := recovery.Complete(attemptID, outcome); err != nil {
		// Trust may be committed. Preserve the pending entry, never fabricate denial.
		s.log().Error("pairing outcome not synchronized", "peer_id", clientID, "attempt_id", attemptID, "error", err)
	}
	if pairErr != nil && !reconciled {
		if errors.Is(pairErr, trust.ErrPairingSecretInvalid) {
			// A denied recovery outcome also requires durable audit proof before
			// it can be acknowledged. Missing completion leaves the record intact.
			denial := audit.Event{
				Time: time.Now().UTC(), Type: "pairing.request", Outcome: "denied",
				ActorID: s.Identity.ID, PeerID: clientID, Transport: transport,
				AttemptID: attemptID, Reason: "invalid_pairing_secret",
			}
			if err := pairingAudit.Append(denial); err != nil {
				s.log().Error("pairing denial completion audit unavailable", "attempt_id", attemptID, "error", err)
			} else if err := recovery.ConfirmCompletion(pairingAudit, attemptID, denial); err != nil {
				s.log().Error("pairing denial audit proof uncertain", "attempt_id", attemptID, "error", err)
			} else if err := recovery.AcknowledgeResolved(attemptID); err != nil {
				s.log().Error("pairing denial recovery archive unavailable", "attempt_id", attemptID, "error", err)
			}
			_ = sendError(conn, "pairing_denied", "invalid or already consumed pairing secret")
			return
		}
		reason := "pairing_secret_consume_failed"
		switch {
		case errors.Is(pairErr, trust.ErrPairingTrustPersist):
			reason = "trust_persist_failed"
		case errors.Is(pairErr, trust.ErrPairingTrustUncertain):
			reason = "trust_commit_uncertain"
		}
		s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "failed", PeerID: clientID, Transport: transport, AttemptID: attemptID, Reason: reason})
		_ = sendError(conn, "server_error", "pairing state unavailable; operator review and new secret required")
		return
	}
	reason := ""
	if reconciled {
		reason = "trust_persist_reconciled"
	}
	completion := audit.Event{
		Time: time.Now().UTC(), Type: "pairing.trust_added", Outcome: "success", ActorID: s.Identity.ID,
		PeerID: clientID, Transport: transport, AttemptID: attemptID, Reason: reason,
	}
	appendCompletion := pairingAudit.Append
	if s.pairingCompletionAudit != nil {
		appendCompletion = func(event audit.Event) error {
			return s.pairingCompletionAudit(pairingAudit, event)
		}
	}
	if err := appendCompletion(completion); err != nil {
		// Trust is already committed. Do not fabricate denial or audit proof.
		s.log().Error("pairing success audit could not be completed", "peer_id", clientID, "error", err)
	} else if err := recovery.ConfirmCompletion(pairingAudit, attemptID, completion); err != nil {
		// A completed audit log line may rotate away; the unconfirmed ledger
		// entry remains and requires privileged, independently audited repair.
		s.log().Error("pairing completion proof not durable", "peer_id", clientID, "attempt_id", attemptID, "error", err)
	} else if err := recovery.AcknowledgeResolved(attemptID); err != nil {
		s.log().Error("pairing recovery archive unavailable", "peer_id", clientID, "attempt_id", attemptID, "error", err)
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePairResponse, Payload: mustJSON(protocol.PairResponse{DeviceID: s.Identity.ID, DeviceName: s.Identity.Name})}); err != nil {
		return
	}
	s.log().Info("paired client", "client_id", clientID, "client_name", name)
}

func (s *Server) handleAuthorizedTerminalWithRouter(conn *tls.Conn, first protocol.Frame, transport, routerID string) {
	peerCert, err := identity.PeerCertificate(conn.ConnectionState())
	if err != nil {
		s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", Transport: transport, Reason: "client_certificate_required"})
		_ = sendError(conn, "unauthorized", "client certificate required")
		return
	}
	clientID := identity.CertificateDeviceID(peerCert)
	fp, err := identity.FingerprintPublicKey(peerCert.PublicKey)
	if err != nil {
		s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_client_certificate"})
		_ = sendError(conn, "unauthorized", "invalid client certificate")
		return
	}
	peer, ok := s.Trust.FindByFingerprint(fp)
	if !ok {
		s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "client_not_paired"})
		_ = sendError(conn, "unauthorized", "client is not paired")
		return
	}
	if clientID == "" || peer.ID != clientID {
		s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "client_identity_mismatch"})
		_ = sendError(conn, "unauthorized", "client identity mismatch")
		return
	}

	var req protocol.OpenAuthorizedSession
	if err := protocol.ParseJSON(first.Payload, &req); err != nil {
		s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_request"})
		_ = sendError(conn, "bad_request", "invalid authorized session request")
		return
	}
	grant := strings.TrimSpace(req.ConnectionGrant)
	if grant == "" || len(grant) > 16*1024 || strings.ContainsAny(grant, "\r\n\t ") {
		s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_connection_grant"})
		_ = sendError(conn, "authorization_denied", "connection authorization failed")
		return
	}
	if s.DirectAuthorizer == nil {
		s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "authorizer_unavailable"})
		_ = sendError(conn, "authorization_unavailable", "direct connection authorization is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.DirectAuthorizer.Authorize(ctx, clientID, s.Identity.ID, grant); err != nil {
		s.log().Warn("direct session authorization rejected", "client_id", clientID, "error", err)
		s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "authorization_rejected"})
		_ = sendError(conn, "authorization_denied", "connection authorization failed")
		return
	}
	s.recordAudit(audit.Event{Type: "terminal.authorization", Outcome: "success", PeerID: clientID, Transport: transport})

	payload, _ := protocol.JSON(protocol.OpenSession{Cols: req.Cols, Rows: req.Rows, Term: req.Term, Capabilities: req.Capabilities})
	s.handleTerminalWithRouter(conn, protocol.Frame{Type: protocol.TypeOpenSession, Payload: payload}, transport, routerID)
}

func (s *Server) handleTerminal(conn *tls.Conn, first protocol.Frame, transport string) {
	s.handleTerminalWithRouter(conn, first, transport, "")
}

func (s *Server) handleTerminalWithRouter(conn *tls.Conn, first protocol.Frame, transport, routerID string) {
	peerCert, err := identity.PeerCertificate(conn.ConnectionState())
	if err != nil {
		s.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "denied", Transport: transport, Reason: "client_certificate_required"})
		_ = sendError(conn, "unauthorized", "client certificate required")
		return
	}
	clientID := identity.CertificateDeviceID(peerCert)
	fp, err := identity.FingerprintPublicKey(peerCert.PublicKey)
	if err != nil {
		s.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_client_certificate"})
		_ = sendError(conn, "unauthorized", "invalid client certificate")
		return
	}
	peer, ok := s.Trust.FindByFingerprint(fp)
	if !ok {
		s.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "client_not_paired"})
		_ = sendError(conn, "unauthorized", "client is not paired")
		return
	}
	if err := s.Policy.Validate(); err != nil {
		s.log().Error("invalid terminal session policy", "error", err)
		s.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "failed", PeerID: peer.ID, Transport: transport, Reason: "session_policy_invalid"})
		_ = sendError(conn, "server_error", "terminal session policy is invalid")
		return
	}
	var open protocol.OpenSession
	if err := protocol.ParseJSON(first.Payload, &open); err != nil {
		s.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: "invalid_request"})
		_ = sendError(conn, "bad_request", "invalid session request")
		return
	}
	fileReady := s.FileTransfer != nil && s.FileTransfer.Ready()
	portForwardReady := s.PortForwarding != nil && s.PortForwarding.Ready()
	capabilities := negotiateSessionCapabilitiesForRuntime(open.Capabilities, true, fileReady, portForwardReady)
	if hasSessionCapability(capabilities, protocol.CapabilityTypedStreamsV1) {
		s.handleTypedTerminalSession(conn, peer.ID, peer.Name, transport, capabilities, routerID)
		return
	}
	if open.Cols == 0 {
		open.Cols = 80
	}
	if open.Rows == 0 {
		open.Rows = 24
	}
	pty, err := terminal.Start(s.Shell, open.Cols, open.Rows, open.Term)
	if err != nil {
		s.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "failed", PeerID: peer.ID, Transport: transport, Reason: "pty_start_failed"})
		_ = sendError(conn, "pty_error", err.Error())
		return
	}
	defer pty.Close()
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeSessionAccepted}); err != nil {
		return
	}
	s.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "success", PeerID: peer.ID, Transport: transport})
	closeReason := "connection_ended"
	defer func() {
		s.recordAudit(audit.Event{Type: "terminal.session_closed", Outcome: "success", PeerID: peer.ID, Transport: transport, Reason: closeReason})
	}()
	s.log().Info("terminal opened", "client_id", peer.ID, "client_name", peer.Name)

	var writeMu sync.Mutex
	writeFrame := func(f protocol.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteFrame(conn, f)
	}

	policyTimers := newSessionPolicyTimers(s.Policy)
	defer policyTimers.Stop()
	activityCh := make(chan struct{}, 1)

	ptyReadDone := make(chan struct{})
	go func() {
		defer close(ptyReadDone)
		buf := make([]byte, 32<<10)
		for {
			n, err := pty.Read(buf)
			if n > 0 {
				data := append([]byte(nil), buf[:n]...)
				if werr := writeFrame(protocol.Frame{Type: protocol.TypeData, StreamID: terminalStreamID, Payload: data}); werr != nil {
					return
				}
				signalSessionActivity(activityCh)
			}
			if err != nil {
				return
			}
		}
	}()

	exitCh := make(chan int, 1)
	go func() { exitCh <- exitCode(pty.Wait()) }()

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
		s.log().Info("terminal policy expired", "client_id", peer.ID, "reason", reason)
		// Bound terminal-output drain before the final close frame. Setting a
		// write deadline first unblocks a PTY forwarding goroutine stuck on a
		// peer that stopped reading.
		_ = pty.Close()
		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			s.log().Warn("terminal close deadline could not be set", "peer_id", peer.ID, "error", err)
			_ = conn.Close()
			return
		}
		if ptyReadDone != nil {
			drainTimer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-ptyReadDone:
				ptyReadDone = nil
			case <-drainTimer.C:
			case <-readErrCh:
			}
			if !drainTimer.Stop() {
				select {
				case <-drainTimer.C:
				default:
				}
			}
		}
		if err := writeFrame(protocol.Frame{Type: protocol.TypeClose, Payload: mustJSON(protocol.Close{ExitCode: sessionPolicyExitCode, Reason: reason})}); err != nil {
			return
		}
		waitForPeerClose(frameCh, readErrCh, 2*time.Second)
	}

	for {
		select {
		case code := <-exitCh:
			closeReason = "process_exit"
			// Cmd.Wait may return before the PTY reader has forwarded the final
			// bytes written by the shell. Close is the protocol's terminal frame,
			// so send it only after PTY output has drained. If draining does not
			// finish promptly, fail closed by dropping the transport without a
			// terminal close frame rather than letting Close overtake output.
			if ptyReadDone != nil {
				err := waitForTerminalDrain(ptyReadDone, readErrCh, terminalExitDrainTimeout)
				switch {
				case err == nil:
					ptyReadDone = nil
				case errors.Is(err, errTerminalDrainTimeout):
					closeReason = "pty_drain_timeout"
					s.log().Warn("terminal output drain timed out", "client_id", peer.ID)
					return
				default:
					closeReason = "peer_disconnect"
					if !errors.Is(err, io.EOF) {
						s.log().Debug("session read ended", "error", err)
					}
					return
				}
			}
			if err := writeFrame(protocol.Frame{Type: protocol.TypeClose, Payload: mustJSON(protocol.Close{ExitCode: code})}); err != nil {
				closeReason = "transport_write_failed"
				return
			}
			// Do not immediately close the outer relay after sending the final
			// application frame. Wait until the client acknowledges it (new
			// clients) or closes its side after receiving it (older clients).
			waitForPeerClose(frameCh, readErrCh, 2*time.Second)
			return
		case err := <-readErrCh:
			closeReason = "peer_disconnect"
			if !errors.Is(err, io.EOF) {
				s.log().Debug("session read ended", "error", err)
			}
			return
		case frame := <-frameCh:
			switch frame.Type {
			case protocol.TypeData:
				if frame.StreamID == terminalStreamID && len(frame.Payload) > 0 {
					if _, err := pty.Write(frame.Payload); err != nil {
						closeReason = "pty_write_failed"
						return
					}
					policyTimers.Activity()
				}
			case protocol.TypeResize:
				var resize protocol.Resize
				if protocol.ParseJSON(frame.Payload, &resize) == nil {
					if pty.Resize(resize.Cols, resize.Rows) == nil {
						policyTimers.Activity()
					}
				}
			case protocol.TypePing:
				_ = writeFrame(protocol.Frame{Type: protocol.TypePong})
			case protocol.TypeClose:
				closeReason = "peer_close"
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
		case <-ptyReadDone:
			// Wait for Cmd.Wait() to provide the authoritative exit code.
			ptyReadDone = nil
		}
	}
}

func waitForTerminalDrain(ptyReadDone <-chan struct{}, readErrCh <-chan error, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ptyReadDone:
		return nil
	case err := <-readErrCh:
		if err == nil {
			return io.EOF
		}
		return err
	case <-timer.C:
		return errTerminalDrainTimeout
	}
}

func waitForPeerClose(frameCh <-chan protocol.Frame, readErrCh <-chan error, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case frame := <-frameCh:
			if frame.Type == protocol.TypeClose {
				return
			}
		case <-readErrCh:
			return
		case <-timer.C:
			return
		}
	}
}

func (s *Server) recordAudit(event audit.Event) {
	if strings.TrimSpace(s.StateDir) == "" {
		return
	}
	if event.ActorID == "" && s.Identity != nil {
		event.ActorID = s.Identity.ID
	}
	log, err := audit.Open(s.StateDir)
	if err == nil {
		err = log.Append(event)
	}
	if err != nil {
		s.log().Warn("persistent audit event failed", "event_type", event.Type, "error", err)
	}
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return 255
}

func cleanName(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return identity.SanitizeName(s)
}

func sendError(w io.Writer, code, message string) error {
	return protocol.WriteFrame(w, protocol.Frame{Type: protocol.TypeError, Payload: mustJSON(protocol.Error{Code: code, Message: message})})
}

func mustJSON(v any) []byte {
	b, err := protocol.JSON(v)
	if err != nil {
		panic(fmt.Sprintf("marshal protocol message: %v", err))
	}
	return b
}

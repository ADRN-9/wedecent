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

const terminalStreamID = 1

type DirectAuthorizer interface {
	Authorize(context.Context, string, string, string) error
}

type Server struct {
	Identity         *identity.Identity
	Trust            *trust.Store
	StateDir         string
	Shell            string
	Logger           *slog.Logger
	DirectAuthorizer DirectAuthorizer
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
	tlsConn := tls.Server(raw, identity.ServerTLS(s.Identity))
	if handshakeTimeout > 0 {
		_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	}
	if err := tlsConn.Handshake(); err != nil {
		s.log().Warn("TLS handshake failed", "remote", raw.RemoteAddr(), "error", err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
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
		s.handleAuthorizedTerminal(tlsConn, first, transport)
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
	ok, err := trust.CheckPairingSecret(s.StateDir, req.PairingSecret)
	if err != nil || !ok {
		s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "denied", PeerID: req.ClientID, Transport: transport, Reason: "invalid_pairing_secret"})
		_ = sendError(conn, "pairing_denied", "invalid pairing secret")
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
	// Consume the high-entropy secret before persisting trust so it cannot be reused.
	if err := invalidatePairingSecret(s.StateDir); err != nil {
		s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "failed", PeerID: clientID, Transport: transport, Reason: "pairing_secret_consume_failed"})
		_ = sendError(conn, "server_error", "could not consume pairing secret")
		return
	}
	if err := s.Trust.Put(trust.Peer{ID: clientID, Name: name, Fingerprint: fp}); err != nil {
		s.recordAudit(audit.Event{Type: "pairing.request", Outcome: "failed", PeerID: clientID, Transport: transport, Reason: "trust_persist_failed"})
		_ = sendError(conn, "server_error", "could not persist trust; generate a new pairing secret")
		return
	}
	s.recordAudit(audit.Event{Type: "pairing.trust_added", Outcome: "success", PeerID: clientID, Transport: transport})
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePairResponse, Payload: mustJSON(protocol.PairResponse{DeviceID: s.Identity.ID, DeviceName: s.Identity.Name})}); err != nil {
		return
	}
	s.log().Info("paired client", "client_id", clientID, "client_name", name)
}

func (s *Server) handleAuthorizedTerminal(conn *tls.Conn, first protocol.Frame, transport string) {
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

	payload, _ := protocol.JSON(protocol.OpenSession{Cols: req.Cols, Rows: req.Rows, Term: req.Term})
	s.handleTerminal(conn, protocol.Frame{Type: protocol.TypeOpenSession, Payload: payload}, transport)
}

func (s *Server) handleTerminal(conn *tls.Conn, first protocol.Frame, transport string) {
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
	var open protocol.OpenSession
	if err := protocol.ParseJSON(first.Payload, &open); err != nil {
		s.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: "invalid_request"})
		_ = sendError(conn, "bad_request", "invalid session request")
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

	for {
		select {
		case code := <-exitCh:
			closeReason = "process_exit"
			// Cmd.Wait may return before the PTY reader has forwarded the final
			// bytes written by the shell. Close is the protocol's terminal frame,
			// so do not send it until PTY output has drained. A disconnected peer
			// still aborts promptly instead of waiting on the PTY indefinitely.
			if ptyReadDone != nil {
				select {
				case <-ptyReadDone:
					ptyReadDone = nil
				case err := <-readErrCh:
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
				if frame.StreamID == terminalStreamID {
					if _, err := pty.Write(frame.Payload); err != nil {
						closeReason = "pty_write_failed"
						return
					}
				}
			case protocol.TypeResize:
				var resize protocol.Resize
				if protocol.ParseJSON(frame.Payload, &resize) == nil {
					_ = pty.Resize(resize.Cols, resize.Rows)
				}
			case protocol.TypePing:
				_ = writeFrame(protocol.Frame{Type: protocol.TypePong})
			case protocol.TypeClose:
				closeReason = "peer_close"
				return
			}
		case <-ptyReadDone:
			// Wait for Cmd.Wait() to provide the authoritative exit code.
			ptyReadDone = nil
		}
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

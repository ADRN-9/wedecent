package session

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/terminal"
	"wedecent.com/wedecent/internal/trust"
)

const terminalStreamID = 1

type Server struct {
	Identity *identity.Identity
	Trust    *trust.Store
	StateDir string
	Shell    string
	Logger   *slog.Logger
}

func (s *Server) ServeConn(raw net.Conn) {
	s.serveConn(raw, 15*time.Second)
}

// ServeParkedRelayConn serves a relay connection that may sit idle until a
// client is matched by the relay. The outer authenticated WebSocket relay is
// responsible for parking the connection; the inner TLS handshake starts only
// when a client arrives, so there is intentionally no pre-client deadline.
func (s *Server) ServeParkedRelayConn(raw net.Conn) {
	s.serveConn(raw, 0)
}

func (s *Server) serveConn(raw net.Conn, handshakeTimeout time.Duration) {
	defer raw.Close()
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
		s.handlePair(tlsConn, first)
	case protocol.TypeOpenSession:
		s.handleTerminal(tlsConn, first)
	default:
		_ = sendError(tlsConn, "unexpected_message", "expected pairing or session request")
	}
}

func (s *Server) handlePair(conn *tls.Conn, first protocol.Frame) {
	peer, err := identity.PeerCertificate(conn.ConnectionState())
	if err != nil {
		_ = sendError(conn, "client_certificate_required", err.Error())
		return
	}
	var req protocol.PairRequest
	if err := protocol.ParseJSON(first.Payload, &req); err != nil {
		_ = sendError(conn, "bad_request", "invalid pair request")
		return
	}
	ok, err := trust.CheckPairingSecret(s.StateDir, req.PairingSecret)
	if err != nil || !ok {
		_ = sendError(conn, "pairing_denied", "invalid pairing secret")
		return
	}
	fp, err := identity.FingerprintPublicKey(peer.PublicKey)
	if err != nil {
		_ = sendError(conn, "pairing_denied", "invalid client key")
		return
	}
	clientID := identity.CertificateDeviceID(peer)
	if clientID == "" || req.ClientID != clientID {
		_ = sendError(conn, "pairing_denied", "client identity mismatch")
		return
	}
	name := cleanName(req.ClientName)
	if name == "" {
		name = peer.Subject.CommonName
	}
	// Consume the high-entropy secret before persisting trust so it cannot be reused.
	if err := invalidatePairingSecret(s.StateDir); err != nil {
		_ = sendError(conn, "server_error", "could not consume pairing secret")
		return
	}
	if err := s.Trust.Put(trust.Peer{ID: clientID, Name: name, Fingerprint: fp}); err != nil {
		_ = sendError(conn, "server_error", "could not persist trust; generate a new pairing secret")
		return
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePairResponse, Payload: mustJSON(protocol.PairResponse{DeviceID: s.Identity.ID, DeviceName: s.Identity.Name})}); err != nil {
		return
	}
	s.log().Info("paired client", "client_id", clientID, "client_name", name)
}

func (s *Server) handleTerminal(conn *tls.Conn, first protocol.Frame) {
	peerCert, err := identity.PeerCertificate(conn.ConnectionState())
	if err != nil {
		_ = sendError(conn, "unauthorized", "client certificate required")
		return
	}
	fp, err := identity.FingerprintPublicKey(peerCert.PublicKey)
	if err != nil {
		_ = sendError(conn, "unauthorized", "invalid client certificate")
		return
	}
	peer, ok := s.Trust.FindByFingerprint(fp)
	if !ok {
		_ = sendError(conn, "unauthorized", "client is not paired")
		return
	}
	var open protocol.OpenSession
	if err := protocol.ParseJSON(first.Payload, &open); err != nil {
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
		_ = sendError(conn, "pty_error", err.Error())
		return
	}
	defer pty.Close()
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeSessionAccepted}); err != nil {
		return
	}
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
			n, err := pty.Master.Read(buf)
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
	go func() { exitCh <- exitCode(pty.Cmd.Wait()) }()

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
			_ = writeFrame(protocol.Frame{Type: protocol.TypeClose, Payload: mustJSON(protocol.Close{ExitCode: code})})
			return
		case err := <-readErrCh:
			if !errors.Is(err, io.EOF) {
				s.log().Debug("session read ended", "error", err)
			}
			return
		case frame := <-frameCh:
			switch frame.Type {
			case protocol.TypeData:
				if frame.StreamID == terminalStreamID {
					if _, err := pty.Master.Write(frame.Payload); err != nil {
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
				return
			}
		case <-ptyReadDone:
			// Wait for Cmd.Wait() to provide the authoritative exit code.
			ptyReadDone = nil
		}
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
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
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

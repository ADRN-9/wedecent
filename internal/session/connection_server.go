package session

import (
	"context"
	"crypto/tls"
	"io"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
)

func (s *Server) handleAuthorizedConnection(conn *tls.Conn, first protocol.Frame) {
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
	clientID := identity.CertificateDeviceID(peerCert)
	if clientID == "" || peer.ID != clientID {
		_ = sendError(conn, "unauthorized", "client identity mismatch")
		return
	}

	var req protocol.OpenAuthorizedConnection
	if err := protocol.ParseJSON(first.Payload, &req); err != nil {
		_ = sendError(conn, "bad_request", "invalid authorized connection request")
		return
	}
	grant := strings.TrimSpace(req.ConnectionGrant)
	if grant == "" || len(grant) > 16*1024 || strings.ContainsAny(grant, "\r\n\t ") {
		_ = sendError(conn, "authorization_denied", "connection authorization failed")
		return
	}
	if s.DirectAuthorizer == nil {
		_ = sendError(conn, "authorization_unavailable", "direct connection authorization is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.DirectAuthorizer.Authorize(ctx, clientID, s.Identity.ID, grant); err != nil {
		s.log().Warn("direct connection authorization rejected", "client_id", clientID, "error", err)
		_ = sendError(conn, "authorization_denied", "connection authorization failed")
		return
	}

	s.handleConnection(conn, protocol.Frame{Type: protocol.TypeOpenConnection})
}

func (s *Server) handleConnection(conn *tls.Conn, first protocol.Frame) {
	if len(first.Payload) != 0 {
		_ = sendError(conn, "bad_request", "connection open request must not contain a payload")
		return
	}
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
	clientID := identity.CertificateDeviceID(peerCert)
	if clientID == "" || peer.ID != clientID {
		_ = sendError(conn, "unauthorized", "client identity mismatch")
		return
	}

	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeConnectionAccepted}); err != nil {
		return
	}
	s.log().Info("connection opened", "client_id", peer.ID, "client_name", peer.Name)

	for {
		frame, err := protocol.ReadFrame(conn)
		if err != nil {
			if err != io.EOF {
				s.log().Debug("connection read ended", "error", err)
			}
			return
		}
		switch frame.Type {
		case protocol.TypePing:
			if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePong}); err != nil {
				return
			}
		case protocol.TypeClose:
			_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeClose})
			return
		default:
			_ = sendError(conn, "unexpected_message", "connection sessions accept only ping or close")
			return
		}
	}
}

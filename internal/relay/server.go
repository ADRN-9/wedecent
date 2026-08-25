package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/relayproto"
)

type Server struct {
	Broker *Broker
	Logger *slog.Logger
}

func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{relayproto.ALPN}}
}

func (s *Server) ServeConn(conn net.Conn) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return
		}
		if tlsConn.ConnectionState().NegotiatedProtocol != relayproto.ALPN {
			_ = conn.Close()
			return
		}
	}
	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		_ = conn.Close()
		return
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := relayproto.Write(conn, relayproto.Message{Type: relayproto.TypeChallenge, Challenge: challenge}); err != nil {
		_ = conn.Close()
		return
	}
	msg, err := relayproto.Read(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	switch msg.Type {
	case relayproto.TypeRegister:
		s.handleRegister(conn, challenge, msg)
	case relayproto.TypeConnect:
		s.handleConnect(conn, msg)
	default:
		_ = relayproto.Write(conn, relayproto.Message{Type: relayproto.TypeError, Code: "bad_request", Error: "expected register or connect"})
		_ = conn.Close()
	}
}

func (s *Server) handleRegister(conn net.Conn, challenge string, msg relayproto.Message) {
	if !validDeviceID(msg.DeviceID) {
		s.reject(conn, "bad_device_id", "invalid device ID")
		return
	}
	pubBytes, err := base64.RawStdEncoding.DecodeString(msg.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		s.reject(conn, "bad_public_key", "invalid Ed25519 public key")
		return
	}
	pub := ed25519.PublicKey(pubBytes)
	if identity.DeviceID(pub) != msg.DeviceID {
		s.reject(conn, "identity_mismatch", "device ID does not match public key")
		return
	}
	sig, err := base64.RawStdEncoding.DecodeString(msg.Signature)
	if err != nil || !ed25519.Verify(pub, relayproto.RegistrationBytes(challenge, msg.DeviceID), sig) {
		s.reject(conn, "bad_signature", "invalid registration signature")
		return
	}
	slot, err := s.Broker.Park(msg.DeviceID, conn)
	if err != nil {
		s.reject(conn, "slot_limit", err.Error())
		return
	}
	if err := relayproto.Write(conn, relayproto.Message{Type: relayproto.TypeWaiting}); err != nil {
		s.Broker.Remove(msg.DeviceID, slot)
		_ = conn.Close()
		return
	}
	select {
	case <-slot.done:
		return
	case <-time.After(6 * time.Minute):
		s.Broker.Remove(msg.DeviceID, slot)
		_ = conn.Close()
	}
}

func (s *Server) handleConnect(client net.Conn, msg relayproto.Message) {
	if !validDeviceID(msg.DeviceID) {
		s.reject(client, "bad_device_id", "invalid device ID")
		return
	}
	slot, err := s.Broker.Take(msg.DeviceID)
	if err != nil {
		s.reject(client, "unavailable", "device has no available outbound relay slot")
		return
	}
	agent := slot.conn
	if err := relayproto.Write(agent, relayproto.Message{Type: relayproto.TypeReady}); err != nil {
		_ = agent.Close()
		slot.finish()
		s.reject(client, "unavailable", "agent relay slot closed")
		return
	}
	if err := relayproto.Write(client, relayproto.Message{Type: relayproto.TypeReady}); err != nil {
		_ = client.Close()
		_ = agent.Close()
		slot.finish()
		return
	}
	s.log().Info("relay session connected", "device_id", msg.DeviceID)
	bridge(client, agent)
	slot.finish()
}

func bridge(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func (s *Server) reject(conn net.Conn, code, message string) {
	_ = relayproto.Write(conn, relayproto.Message{Type: relayproto.TypeError, Code: code, Error: message})
	_ = conn.Close()
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func validDeviceID(id string) bool {
	if len(id) != 19 || !strings.HasPrefix(id, "wd_") {
		return false
	}
	for _, r := range id[3:] {
		if (r < 'a' || r > 'z') && (r < '2' || r > '7') {
			return false
		}
	}
	return true
}

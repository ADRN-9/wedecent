package session

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/terminal"
	"wedecent.com/wedecent/internal/trust"
)

const (
	activeSessionRevocationPollInterval = 100 * time.Millisecond
	sessionAdmissionWriteTimeout        = 2 * time.Second
)

var errSessionAdmissionWrite = errors.New("terminal session admission write failed")

type terminalSessionPTY interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Resize(uint16, uint16) error
	Wait() error
	Close() error
}

type terminalPTYStarter func(string, uint16, uint16, string) (terminalSessionPTY, error)

type activeTerminalSession struct {
	server      *Server
	ID          string
	clientID    string
	fingerprint string
	generation  string
	transport   string
	rawConn     net.Conn

	mu              sync.Mutex
	finished        bool
	terminated      bool
	reason          string
	cleanup         func()
	done            chan struct{}
	terminationDone chan struct{}
	finishOnce      sync.Once
}

func (s *Server) startTerminal(shell string, cols, rows uint16, term string) (terminalSessionPTY, error) {
	if s.terminalStart != nil {
		return s.terminalStart(shell, cols, rows, term)
	}
	return terminal.Start(shell, cols, rows, term)
}

// admitTerminalSession reserves admission under the trust-store mutation lock.
// Lock order is trust-store file lock -> Store.mu -> activeSessionsMu. The
// watcher releases activeSessionsMu before reading the trust snapshot, so it
// never acquires these locks in reverse order. A nil accept callback creates a
// reservation that callers may initialize (for example, start a PTY) afterward.
func (s *Server) admitTerminalSession(clientID, fingerprint, transport string, rawConn net.Conn, cleanup func(), accept func(string) error) (*activeTerminalSession, error) {
	if s == nil || s.Trust == nil {
		return nil, errors.New("terminal trust store is unavailable")
	}
	if rawConn == nil {
		return nil, errors.New("terminal session transport is unavailable")
	}

	var active *activeTerminalSession
	err := s.Trust.WithTrustedPeer(clientID, fingerprint, func(peer trust.Peer) error {
		sessionID, err := newTerminalSessionID()
		if err != nil {
			return err
		}
		active = &activeTerminalSession{
			server:          s,
			ID:              sessionID,
			clientID:        peer.ID,
			fingerprint:     peer.Fingerprint,
			generation:      peer.Generation,
			transport:       transport,
			rawConn:         rawConn,
			cleanup:         cleanup,
			done:            make(chan struct{}),
			terminationDone: make(chan struct{}),
		}
		s.activeSessionsMu.Lock()
		if s.activeSessions == nil {
			s.activeSessions = make(map[string]*activeTerminalSession)
		}
		s.activeSessions[sessionID] = active
		s.activeSessionsMu.Unlock()

		if accept != nil {
			if err := accept(sessionID); err != nil {
				active.finish()
				return fmt.Errorf("%w: %v", errSessionAdmissionWrite, err)
			}
		}
		return nil
	})
	if err != nil {
		if active != nil {
			active.finish()
		}
		return nil, err
	}
	s.startActiveSessionWatcher()
	return active, nil
}

func sessionAdmissionFailure(err error) (code, reason string) {
	switch {
	case errors.Is(err, errSessionAdmissionWrite):
		return "transport_error", "session_accept_failed"
	case errors.Is(err, trust.ErrPeerNotFound):
		return "unauthorized", "client_revoked"
	case errors.Is(err, trust.ErrPeerIdentityMismatch):
		return "unauthorized", "client_identity_mismatch"
	default:
		return "authorization_unavailable", "trust_store_unavailable"
	}
}

func writeSessionAccepted(conn net.Conn, frame protocol.Frame) error {
	if conn == nil {
		return errors.New("terminal connection is unavailable")
	}
	if err := conn.SetWriteDeadline(time.Now().Add(sessionAdmissionWriteTimeout)); err != nil {
		return fmt.Errorf("set terminal session admission write deadline: %w", err)
	}
	writeErr := protocol.WriteFrame(conn, frame)
	clearErr := conn.SetWriteDeadline(time.Time{})
	if writeErr != nil {
		return writeErr
	}
	if clearErr != nil {
		return fmt.Errorf("clear terminal session admission write deadline: %w", clearErr)
	}
	return nil
}

func newTerminalSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("create terminal session ID: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func (s *Server) startActiveSessionWatcher() {
	s.activeSessionsMu.Lock()
	if len(s.activeSessions) != 0 && !s.activeSessionsRunning {
		s.activeSessionsRunning = true
		go s.watchActiveSessions()
	}
	s.activeSessionsMu.Unlock()
}

func (s *Server) watchActiveSessions() {
	ticker := time.NewTicker(activeSessionRevocationPollInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.activeSessionsMu.Lock()
		if len(s.activeSessions) == 0 {
			s.activeSessionsRunning = false
			s.activeSessionsMu.Unlock()
			return
		}
		sessions := make([]*activeTerminalSession, 0, len(s.activeSessions))
		for _, active := range s.activeSessions {
			sessions = append(sessions, active)
		}
		s.activeSessionsMu.Unlock()

		snapshot, err := s.Trust.Snapshot()
		if err != nil {
			for _, active := range sessions {
				active.terminateAsync("trust_store_unavailable")
			}
			continue
		}
		for _, active := range sessions {
			peer, ok := snapshot[active.clientID]
			switch {
			case !ok:
				active.terminateAsync("client_revoked")
			case peer.Fingerprint != active.fingerprint:
				active.terminateAsync("client_identity_changed")
			case peer.Generation != active.generation:
				active.terminateAsync("client_revoked")
			}
		}
	}
}

func (a *activeTerminalSession) setCleanup(cleanup func()) {
	if a == nil || cleanup == nil {
		return
	}
	a.mu.Lock()
	if a.finished {
		a.mu.Unlock()
		return
	}
	if a.terminated {
		a.mu.Unlock()
		cleanup()
		return
	}
	a.cleanup = cleanup
	a.mu.Unlock()
}

func (a *activeTerminalSession) beginTermination(reason string) (func(), bool) {
	if a == nil {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.finished || a.terminated {
		return nil, false
	}
	a.terminated = true
	a.reason = reason
	cleanup := a.cleanup
	a.cleanup = nil
	return cleanup, true
}

func (a *activeTerminalSession) terminate(reason string) {
	cleanup, ok := a.beginTermination(reason)
	if ok {
		a.closeAndAudit(reason, cleanup)
	}
}

func (a *activeTerminalSession) terminateAsync(reason string) {
	cleanup, ok := a.beginTermination(reason)
	if !ok {
		return
	}
	go a.closeAndAudit(reason, cleanup)
}

func (a *activeTerminalSession) closeAndAudit(reason string, cleanup func()) {
	if a.terminationDone != nil {
		defer close(a.terminationDone)
	}
	// Abort unwraps TLS and WebSocket adapters to the transport socket. It
	// never acquires their write mutexes or sends graceful close records.
	if a.rawConn != nil {
		_ = abortSessionTransport(a.rawConn)
	}
	if cleanup != nil {
		cleanup()
	}
	if err := a.server.appendAudit(audit.Event{
		Type:      "terminal.session_terminated",
		Outcome:   "success",
		PeerID:    a.clientID,
		SessionID: a.ID,
		Transport: a.transport,
		Reason:    reason,
	}); err != nil {
		a.server.log().Error("terminal session termination audit failed", "client_id", a.clientID, "session_id", a.ID, "error", err)
	}
}

// abortSessionTransport bypasses graceful TLS shutdown and any adapter-level
// write locks. TLS wrappers expose their underlying transport through NetConn.
func abortSessionTransport(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		return abortSessionTransport(tlsConn.NetConn())
	}
	if aborter, ok := conn.(interface{ Abort() error }); ok {
		return aborter.Abort()
	}
	return conn.Close()
}

func (a *activeTerminalSession) finish() {
	if a == nil {
		return
	}
	a.finishOnce.Do(func() {
		a.mu.Lock()
		a.finished = true
		terminated := a.terminated
		terminationDone := a.terminationDone
		a.cleanup = nil
		a.mu.Unlock()
		if terminated && terminationDone != nil {
			<-terminationDone
		}
		close(a.done)
		a.server.activeSessionsMu.Lock()
		delete(a.server.activeSessions, a.ID)
		a.server.activeSessionsMu.Unlock()
	})
}

func (a *activeTerminalSession) reasonOr(fallback string) string {
	if a == nil {
		return fallback
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reason != "" {
		return a.reason
	}
	return fallback
}

func (a *activeTerminalSession) isTerminated() bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.terminated
}

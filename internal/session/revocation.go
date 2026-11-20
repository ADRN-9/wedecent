package session

import (
	"crypto/rand"
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
	conn        net.Conn

	mu         sync.Mutex
	finished   bool
	terminated bool
	reason     string
	cleanup    func()
	done       chan struct{}
	finishOnce sync.Once
}

func (s *Server) startTerminal(shell string, cols, rows uint16, term string) (terminalSessionPTY, error) {
	if s.terminalStart != nil {
		return s.terminalStart(shell, cols, rows, term)
	}
	return terminal.Start(shell, cols, rows, term)
}

// admitTerminalSession linearizes session acceptance with cross-process
// trust revocation. The short acceptance write runs under the trust-store lock:
// either revocation commits first and admission fails, or acceptance completes
// first and the newly active session is terminated by the revocation watcher.
func (s *Server) admitTerminalSession(clientID, fingerprint, transport string, conn net.Conn, cleanup func(), accept func(string) error) (*activeTerminalSession, error) {
	if s == nil || s.Trust == nil {
		return nil, errors.New("terminal trust store is unavailable")
	}
	if conn == nil || accept == nil {
		return nil, errors.New("terminal session admission is incomplete")
	}

	var active *activeTerminalSession
	err := s.Trust.WithTrustedPeer(clientID, fingerprint, func(peer trust.Peer) error {
		sessionID, err := newTerminalSessionID()
		if err != nil {
			return err
		}
		active = &activeTerminalSession{
			server:      s,
			ID:          sessionID,
			clientID:    peer.ID,
			fingerprint: peer.Fingerprint,
			generation:  peer.Generation,
			transport:   transport,
			conn:        conn,
			cleanup:     cleanup,
			done:        make(chan struct{}),
		}
		s.activeSessionsMu.Lock()
		if s.activeSessions == nil {
			s.activeSessions = make(map[string]*activeTerminalSession)
		}
		s.activeSessions[sessionID] = active
		s.activeSessionsMu.Unlock()

		if err := accept(sessionID); err != nil {
			active.finish()
			return fmt.Errorf("%w: %v", errSessionAdmissionWrite, err)
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
	_ = conn.SetWriteDeadline(time.Now().Add(sessionAdmissionWriteTimeout))
	err := protocol.WriteFrame(conn, frame)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
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
				active.terminate("trust_store_unavailable")
			}
			continue
		}
		for _, active := range sessions {
			peer, ok := snapshot[active.clientID]
			switch {
			case !ok:
				active.terminate("client_revoked")
			case peer.Fingerprint != active.fingerprint:
				active.terminate("client_identity_changed")
			case peer.Generation != active.generation:
				active.terminate("client_revoked")
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

func (a *activeTerminalSession) terminate(reason string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.finished || a.terminated {
		a.mu.Unlock()
		return
	}
	a.terminated = true
	a.reason = reason
	cleanup := a.cleanup
	a.mu.Unlock()

	// Tear down the PTY/ConPTY before closing TLS. In particular, TLS
	// close_notify can wait for the peer to read; resource cleanup must not
	// depend on transport shutdown completing first.
	if cleanup != nil {
		cleanup()
	}
	_ = a.conn.Close()
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

func (a *activeTerminalSession) finish() {
	if a == nil {
		return
	}
	a.finishOnce.Do(func() {
		a.mu.Lock()
		a.finished = true
		a.cleanup = nil
		a.mu.Unlock()
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

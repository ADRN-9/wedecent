package session

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

// ManagedTerminal is a lifecycle-only terminal session used by the Local Core
// connection manager. It establishes the same authorized application session as
// ConnectTerminal, drains terminal output so the remote PTY cannot block, and
// exposes only close/lifecycle state. A future terminal-stream API can replace
// the drain with an explicit bounded UI stream without changing authorization.
type ManagedTerminal struct {
	conn *tls.Conn

	writeMu sync.Mutex
	endOnce sync.Once
	done    chan struct{}
}

// OpenManagedTerminal establishes an authenticated terminal application
// session without binding it to process stdin/stdout. Authorization semantics
// intentionally match ConnectTerminal: non-WebSocket-relay transports carry the
// connection grant in-band, while wsrelay carries it in the outer relay request.
func (c *Client) OpenManagedTerminal(ctx context.Context, peer trust.Peer, cols, rows uint16, term string) (*ManagedTerminal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inBandAuthorization := !strings.HasPrefix(strings.ToLower(strings.TrimSpace(peer.Endpoint)), "wsrelay://")
	if inBandAuthorization {
		grant := strings.TrimSpace(c.ConnectionGrant)
		if grant == "" || len(grant) > 16*1024 || strings.ContainsAny(grant, "\r\n\t ") {
			return nil, errors.New("a valid connection grant is required for this transport")
		}
	}
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	raw, err := c.dial(ctx, peer.Endpoint)
	if err != nil {
		return nil, err
	}
	conn, err := tlsClientContext(ctx, raw, c.Identity, peer.Fingerprint)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	deadline := time.Now().Add(15 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	frameType := protocol.TypeOpenSession
	var payload []byte
	if inBandAuthorization {
		frameType = protocol.TypeOpenAuthorizedSession
		payload, _ = protocol.JSON(protocol.OpenAuthorizedSession{
			Cols: cols, Rows: rows, Term: term, ConnectionGrant: strings.TrimSpace(c.ConnectionGrant),
		})
	} else {
		payload, _ = protocol.JSON(protocol.OpenSession{Cols: cols, Rows: rows, Term: term})
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: frameType, Payload: payload}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	first, err := protocol.ReadFrame(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if first.Type == protocol.TypeError {
		_ = conn.Close()
		return nil, protocolError(first.Payload)
	}
	if first.Type != protocol.TypeSessionAccepted {
		_ = conn.Close()
		return nil, errors.New("session was not accepted")
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	managed := &ManagedTerminal{conn: conn, done: make(chan struct{})}
	go managed.monitor()
	return managed, nil
}

func (s *ManagedTerminal) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

func (s *ManagedTerminal) Close() error {
	if s == nil {
		return nil
	}
	select {
	case <-s.done:
		return nil
	default:
	}

	// Graceful application close is best-effort; the TLS close below is the
	// authoritative teardown and unblocks the monitor even if the peer vanished.
	_ = s.writeFrame(protocol.Frame{Type: protocol.TypeClose})
	return s.finish()
}

func (s *ManagedTerminal) monitor() {
	for {
		frame, err := protocol.ReadFrame(s.conn)
		if err != nil {
			_ = s.finish()
			return
		}
		switch frame.Type {
		case protocol.TypeClose:
			_ = s.writeFrame(protocol.Frame{Type: protocol.TypeClose})
			_ = s.finish()
			return
		case protocol.TypePing:
			if err := s.writeFrame(protocol.Frame{Type: protocol.TypePong}); err != nil {
				_ = s.finish()
				return
			}
		case protocol.TypeError:
			_ = s.finish()
			return
		case protocol.TypeData, protocol.TypePong, protocol.TypeResize:
			// Lifecycle-only sessions deliberately drain application frames. This
			// keeps the remote PTY from blocking without retaining terminal data.
		default:
			// The lifecycle-only core endpoint has no reason to accept protocol
			// extensions implicitly. Unexpected frames terminate the session.
			_ = s.finish()
			return
		}
	}
}

func (s *ManagedTerminal) writeFrame(frame protocol.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return protocol.WriteFrame(s.conn, frame)
}

func (s *ManagedTerminal) finish() error {
	var closeErr error
	s.endOnce.Do(func() {
		closeErr = s.conn.Close()
		close(s.done)
	})
	return closeErr
}

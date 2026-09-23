package session

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

const (
	managedTerminalCloseTimeout = time.Second
	managedTerminalWriteTimeout = 10 * time.Second
	managedTerminalOutputLimit  = 256 << 10
	managedTerminalChunkLimit   = 32 << 10
)

// ManagedTerminal is the authenticated terminal session used by Local Core.
// Remote output is retained only in a bounded in-memory queue. A slow or absent
// consumer cannot cause unbounded memory growth; if the queue fills, the session
// is terminated rather than silently dropping terminal bytes.
type ManagedTerminal struct {
	conn *tls.Conn

	writeMu sync.Mutex
	readMu  sync.Mutex

	outputMu     sync.Mutex
	outputQueue  [][]byte
	outputBytes  int
	outputNotify chan struct{}

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

	managed := &ManagedTerminal{
		conn:         conn,
		done:         make(chan struct{}),
		outputNotify: make(chan struct{}, 1),
	}
	go managed.monitor()
	return managed, nil
}

func (s *ManagedTerminal) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

// ReadTerminal returns up to maxBytes of buffered PTY output. It blocks until
// output arrives, the session closes, or ctx is canceled. At most one reader is
// serviced at a time so terminal byte ordering is deterministic.
func (s *ManagedTerminal) ReadTerminal(ctx context.Context, maxBytes int) ([]byte, bool, error) {
	if s == nil {
		return nil, true, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if maxBytes == 0 {
		maxBytes = managedTerminalChunkLimit
	}
	if maxBytes < 1 || maxBytes > managedTerminalChunkLimit {
		return nil, false, errors.New("terminal read size is out of range")
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		s.outputMu.Lock()
		if len(s.outputQueue) != 0 {
			chunk := s.outputQueue[0]
			n := len(chunk)
			if n > maxBytes {
				n = maxBytes
			}
			out := append([]byte(nil), chunk[:n]...)
			if n == len(chunk) {
				s.outputQueue[0] = nil
				s.outputQueue = s.outputQueue[1:]
			} else {
				s.outputQueue[0] = chunk[n:]
			}
			s.outputBytes -= n
			closed := channelClosed(s.done) && s.outputBytes == 0
			s.outputMu.Unlock()
			return out, closed, nil
		}
		closed := channelClosed(s.done)
		s.outputMu.Unlock()
		if closed {
			return nil, true, nil
		}

		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-s.done:
			// Loop once more so bytes queued before the terminal close are drained.
		case <-s.outputNotify:
		}
	}
}

// WriteTerminal writes bounded input bytes to the remote PTY.
func (s *ManagedTerminal) WriteTerminal(ctx context.Context, data []byte) error {
	if s == nil {
		return io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) < 1 || len(data) > managedTerminalChunkLimit {
		return errors.New("terminal write size is out of range")
	}
	if channelClosed(s.done) {
		return io.ErrClosedPipe
	}
	payload := append([]byte(nil), data...)
	return s.writeFrameContext(ctx, protocol.Frame{
		Type:     protocol.TypeData,
		StreamID: terminalStreamID,
		Payload:  payload,
	})
}

// ResizeTerminal updates the remote PTY size for an active terminal.
func (s *ManagedTerminal) ResizeTerminal(ctx context.Context, cols, rows uint16) error {
	if s == nil {
		return io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if cols == 0 || rows == 0 {
		return errors.New("terminal size must be non-zero")
	}
	if channelClosed(s.done) {
		return io.ErrClosedPipe
	}
	payload, err := protocol.JSON(protocol.Resize{Cols: cols, Rows: rows})
	if err != nil {
		return err
	}
	return s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeResize, Payload: payload})
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
		case protocol.TypeData:
			if frame.StreamID == terminalStreamID && len(frame.Payload) != 0 {
				if !s.enqueueOutput(frame.Payload) {
					_ = s.finish()
					return
				}
			}
		case protocol.TypePong, protocol.TypeResize:
			// Pong and peer resize frames do not carry UI terminal output.
		default:
			// Do not accept protocol extensions implicitly at the Local Core
			// boundary. Unexpected frames terminate the session fail-closed.
			_ = s.finish()
			return
		}
	}
}

func (s *ManagedTerminal) enqueueOutput(data []byte) bool {
	copyData := append([]byte(nil), data...)
	s.outputMu.Lock()
	if len(copyData) > managedTerminalOutputLimit-s.outputBytes {
		s.outputMu.Unlock()
		return false
	}
	s.outputQueue = append(s.outputQueue, copyData)
	s.outputBytes += len(copyData)
	s.outputMu.Unlock()
	select {
	case s.outputNotify <- struct{}{}:
	default:
	}
	return true
}

func (s *ManagedTerminal) writeFrame(frame protocol.Frame) error {
	return s.writeFrameContext(context.Background(), frame)
}

func (s *ManagedTerminal) writeFrameContext(ctx context.Context, frame protocol.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(managedTerminalWriteTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = s.conn.SetWriteDeadline(deadline)
	defer s.conn.SetWriteDeadline(time.Time{})
	if err := protocol.WriteFrame(s.conn, frame); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	return nil
}

func (s *ManagedTerminal) finish() error {
	var closeErr error
	s.endOnce.Do(func() {
		// Lifecycle completion is authoritative as soon as the application
		// protocol ends. Buffered terminal output remains readable after done is
		// closed; the Local Core service retains the handle for a bounded grace
		// period so final PTY bytes are not lost on remote exit.
		close(s.done)
		select {
		case s.outputNotify <- struct{}{}:
		default:
		}
		_ = s.conn.SetDeadline(time.Now().Add(managedTerminalCloseTimeout))
		closeErr = s.conn.Close()
	})
	return closeErr
}

func channelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

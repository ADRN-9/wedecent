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
	managedMuxReceiveWindow = 256 << 10
	managedMuxMaxStreams    = 8
	managedMuxMaxAllocated  = 256
)

type managedMuxChild struct {
	id uint32

	readMu sync.Mutex
	mu     sync.Mutex

	outputQueue  [][]byte
	outputBytes  int
	outputNotify chan struct{}

	sendCredit   uint32
	recvCredit   uint32
	creditNotify chan struct{}

	accepted   chan error
	acceptOnce sync.Once
	done       chan struct{}
	closeOnce  sync.Once
}

// ManagedMultiplexTerminal owns one authenticated parent application session.
// When typed-streams-v1 is negotiated it may own multiple independent terminal
// children. If the peer does not echo the capability, the handle transparently
// preserves the legacy stream-1 terminal behavior.
type ManagedMultiplexTerminal struct {
	conn *tls.Conn

	writeMu   sync.Mutex
	probeMu   sync.Mutex
	probePong chan struct{}

	mu            sync.Mutex
	typed         bool
	streams       map[uint32]*managedMuxChild
	defaultStream uint32
	nextStream    uint32
	allocated     int

	endOnce sync.Once
	done    chan struct{}
}

// OpenManagedMultiplexTerminal requests typed-streams-v1 but falls back to the
// exact legacy terminal framing when the peer does not echo the capability.
func (c *Client) OpenManagedMultiplexTerminal(ctx context.Context, peer trust.Peer, cols, rows uint16, term string) (*ManagedMultiplexTerminal, error) {
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

	capabilities := []protocol.Capability{protocol.CapabilityTypedStreamsV1}
	frameType := protocol.TypeOpenSession
	var payload []byte
	if inBandAuthorization {
		frameType = protocol.TypeOpenAuthorizedSession
		payload, _ = protocol.JSON(protocol.OpenAuthorizedSession{
			Cols: cols, Rows: rows, Term: term,
			ConnectionGrant: strings.TrimSpace(c.ConnectionGrant),
			Capabilities:    capabilities,
		})
	} else {
		payload, _ = protocol.JSON(protocol.OpenSession{Cols: cols, Rows: rows, Term: term, Capabilities: capabilities})
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

	typed := false
	if len(first.Payload) != 0 {
		var accepted protocol.SessionAccepted
		if err := protocol.ParseTypedStreamJSON(first.Payload, &accepted); err != nil {
			_ = conn.Close()
			return nil, errors.New("invalid session capabilities")
		}
		if len(accepted.Capabilities) != 1 || accepted.Capabilities[0] != protocol.CapabilityTypedStreamsV1 {
			_ = conn.Close()
			return nil, errors.New("unexpected session capabilities")
		}
		typed = true
	}
	_ = conn.SetDeadline(time.Time{})

	s := &ManagedMultiplexTerminal{
		conn:       conn,
		typed:      typed,
		streams:    make(map[uint32]*managedMuxChild),
		nextStream: protocol.MinTypedStreamID,
		probePong:  make(chan struct{}, 1),
		done:       make(chan struct{}),
	}
	if !typed {
		child := newManagedMuxChild(terminalStreamID, false)
		s.streams[terminalStreamID] = child
		s.defaultStream = terminalStreamID
	}
	go s.monitor()
	if typed {
		streamID, err := s.OpenTerminalStream(ctx, cols, rows, term)
		if err != nil {
			_ = s.finish()
			return nil, err
		}
		s.mu.Lock()
		s.defaultStream = streamID
		s.mu.Unlock()
	}
	return s, nil
}

func newManagedMuxChild(id uint32, typed bool) *managedMuxChild {
	child := &managedMuxChild{
		id:           id,
		outputNotify: make(chan struct{}, 1),
		creditNotify: make(chan struct{}, 1),
		accepted:     make(chan error, 1),
		done:         make(chan struct{}),
	}
	if typed {
		child.recvCredit = managedMuxReceiveWindow
	}
	return child
}

func (s *ManagedMultiplexTerminal) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

func (s *ManagedMultiplexTerminal) ProbeLatency(ctx context.Context) (time.Duration, error) {
	if s == nil || channelClosed(s.done) {
		return 0, io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	select {
	case <-s.probePong:
	default:
	}
	started := time.Now()
	if err := s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypePing}); err != nil {
		return 0, err
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-s.done:
		return 0, io.ErrClosedPipe
	case <-s.probePong:
		return time.Since(started), nil
	}
}

func (s *ManagedMultiplexTerminal) ReadTerminal(ctx context.Context, maxBytes int) ([]byte, bool, error) {
	id, err := s.defaultStreamID()
	if err != nil {
		return nil, true, err
	}
	return s.ReadTerminalStream(ctx, id, maxBytes)
}

func (s *ManagedMultiplexTerminal) WriteTerminal(ctx context.Context, data []byte) error {
	id, err := s.defaultStreamID()
	if err != nil {
		return err
	}
	return s.WriteTerminalStream(ctx, id, data)
}

func (s *ManagedMultiplexTerminal) ResizeTerminal(ctx context.Context, cols, rows uint16) error {
	id, err := s.defaultStreamID()
	if err != nil {
		return err
	}
	return s.ResizeTerminalStream(ctx, id, cols, rows)
}

func (s *ManagedMultiplexTerminal) defaultStreamID() (uint32, error) {
	if s == nil || channelClosed(s.done) {
		return 0, io.ErrClosedPipe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.defaultStream == 0 {
		return 0, io.ErrClosedPipe
	}
	return s.defaultStream, nil
}

func (s *ManagedMultiplexTerminal) OpenTerminalStream(ctx context.Context, cols, rows uint16, term string) (uint32, error) {
	if s == nil || channelClosed(s.done) {
		return 0, io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if cols == 0 || rows == 0 {
		return 0, errors.New("terminal size must be non-zero")
	}
	s.mu.Lock()
	if !s.typed {
		s.mu.Unlock()
		return 0, errors.New("typed terminal streams were not negotiated")
	}
	if len(s.streams) >= managedMuxMaxStreams || s.allocated >= managedMuxMaxAllocated {
		s.mu.Unlock()
		return 0, errors.New("terminal stream limit reached")
	}
	id := s.nextStream
	if id < protocol.MinTypedStreamID {
		id = protocol.MinTypedStreamID
	}
	for {
		if _, exists := s.streams[id]; !exists {
			break
		}
		id++
	}
	s.nextStream = id + 1
	s.allocated++
	child := newManagedMuxChild(id, true)
	s.streams[id] = child
	s.mu.Unlock()

	payload, err := protocol.JSON(protocol.StreamOpen{
		Kind: protocol.StreamKindTerminal, Cols: cols, Rows: rows, Term: term,
		InitialWindow: managedMuxReceiveWindow,
	})
	if err != nil {
		s.removeChild(id)
		return 0, err
	}
	if err := s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: id, Payload: payload}); err != nil {
		s.removeChild(id)
		return 0, err
	}
	select {
	case <-ctx.Done():
		s.removeChild(id)
		return 0, ctx.Err()
	case <-s.done:
		return 0, io.ErrClosedPipe
	case err := <-child.accepted:
		if err != nil {
			s.removeChild(id)
			return 0, err
		}
		return id, nil
	}
}

func (s *ManagedMultiplexTerminal) ReadTerminalStream(ctx context.Context, id uint32, maxBytes int) ([]byte, bool, error) {
	child, typed, err := s.child(id)
	if err != nil {
		return nil, true, err
	}
	if maxBytes == 0 {
		maxBytes = managedTerminalChunkLimit
	}
	if maxBytes < 1 || maxBytes > managedTerminalChunkLimit {
		return nil, false, errors.New("terminal read size is out of range")
	}
	child.readMu.Lock()
	defer child.readMu.Unlock()
	for {
		child.mu.Lock()
		if len(child.outputQueue) != 0 {
			chunk := child.outputQueue[0]
			n := len(chunk)
			if n > maxBytes {
				n = maxBytes
			}
			out := append([]byte(nil), chunk[:n]...)
			if n == len(chunk) {
				child.outputQueue[0] = nil
				child.outputQueue = child.outputQueue[1:]
			} else {
				child.outputQueue[0] = chunk[n:]
			}
			child.outputBytes -= n
			closed := channelClosed(child.done) && child.outputBytes == 0
			child.mu.Unlock()
			if typed && n > 0 {
				payload, _ := protocol.JSON(protocol.StreamWindowUpdate{Bytes: uint32(n)})
				if err := s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: id, Payload: payload}); err != nil {
					_ = s.finish()
					return out, true, err
				}
				child.mu.Lock()
				child.recvCredit += uint32(n)
				child.mu.Unlock()
			}
			return out, closed, nil
		}
		closed := channelClosed(child.done)
		child.mu.Unlock()
		if closed {
			return nil, true, nil
		}
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-s.done:
			return nil, true, io.ErrClosedPipe
		case <-child.done:
		case <-child.outputNotify:
		}
	}
}

func (s *ManagedMultiplexTerminal) WriteTerminalStream(ctx context.Context, id uint32, data []byte) error {
	child, typed, err := s.child(id)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) < 1 || len(data) > managedTerminalChunkLimit {
		return errors.New("terminal write size is out of range")
	}
	if !typed {
		return s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeData, StreamID: terminalStreamID, Payload: append([]byte(nil), data...)})
	}
	remaining := data
	for len(remaining) != 0 {
		var n int
		for n == 0 {
			child.mu.Lock()
			if channelClosed(child.done) {
				child.mu.Unlock()
				return io.ErrClosedPipe
			}
			if child.sendCredit > 0 {
				n = len(remaining)
				if n > protocol.MaxTypedStreamChunk {
					n = protocol.MaxTypedStreamChunk
				}
				if uint32(n) > child.sendCredit {
					n = int(child.sendCredit)
				}
				child.sendCredit -= uint32(n)
			}
			child.mu.Unlock()
			if n == 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-s.done:
					return io.ErrClosedPipe
				case <-child.done:
					return io.ErrClosedPipe
				case <-child.creditNotify:
				}
			}
		}
		if err := s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamData, StreamID: id, Payload: append([]byte(nil), remaining[:n]...)}); err != nil {
			return err
		}
		remaining = remaining[n:]
	}
	return nil
}

func (s *ManagedMultiplexTerminal) ResizeTerminalStream(ctx context.Context, id uint32, cols, rows uint16) error {
	_, typed, err := s.child(id)
	if err != nil {
		return err
	}
	if cols == 0 || rows == 0 {
		return errors.New("terminal size must be non-zero")
	}
	payload, err := protocol.JSON(protocol.Resize{Cols: cols, Rows: rows})
	if err != nil {
		return err
	}
	frameType := protocol.TypeResize
	streamID := uint32(0)
	if typed {
		frameType = protocol.TypeStreamResize
		streamID = id
	}
	return s.writeFrameContext(ctx, protocol.Frame{Type: frameType, StreamID: streamID, Payload: payload})
}

func (s *ManagedMultiplexTerminal) CloseTerminalStream(ctx context.Context, id uint32) error {
	_, typed, err := s.child(id)
	if err != nil {
		return err
	}
	if !typed {
		return s.Close()
	}
	payload, _ := protocol.JSON(protocol.StreamClose{Reason: "client_close"})
	if err := s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamClose, StreamID: id, Payload: payload}); err != nil {
		return err
	}
	s.closeChild(id)
	return nil
}

func (s *ManagedMultiplexTerminal) child(id uint32) (*managedMuxChild, bool, error) {
	if s == nil || channelClosed(s.done) {
		return nil, false, io.ErrClosedPipe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	child := s.streams[id]
	if child == nil {
		return nil, s.typed, errors.New("terminal stream is unavailable")
	}
	return child, s.typed, nil
}

func (s *ManagedMultiplexTerminal) Close() error {
	if s == nil {
		return nil
	}
	select {
	case <-s.done:
		return nil
	default:
	}
	_ = s.writeFrame(protocol.Frame{Type: protocol.TypeClose})
	return s.finish()
}

func (s *ManagedMultiplexTerminal) monitor() {
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
			if s.writeFrame(protocol.Frame{Type: protocol.TypePong}) != nil {
				_ = s.finish()
				return
			}
		case protocol.TypePong:
			select {
			case s.probePong <- struct{}{}:
			default:
			}
		case protocol.TypeError:
			_ = s.finish()
			return
		case protocol.TypeData:
			if s.isTyped() || frame.StreamID != terminalStreamID || len(frame.Payload) == 0 {
				_ = s.finish()
				return
			}
			if !s.enqueue(frame.StreamID, frame.Payload, false) {
				_ = s.finish()
				return
			}
		case protocol.TypeResize:
			if s.isTyped() {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamAccepted:
			if !s.handleAccepted(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamData:
			if !s.handleTypedData(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamWindowUpdate:
			if !s.handleWindowUpdate(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamClose:
			if !s.handleStreamClose(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamError:
			if !s.handleStreamError(frame) {
				_ = s.finish()
				return
			}
		default:
			_ = s.finish()
			return
		}
	}
}

func (s *ManagedMultiplexTerminal) isTyped() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.typed }

func (s *ManagedMultiplexTerminal) handleAccepted(frame protocol.Frame) bool {
	if !s.isTyped() {
		return false
	}
	var accepted protocol.StreamAccepted
	if protocol.ParseTypedStreamJSON(frame.Payload, &accepted) != nil || protocol.ValidateStreamAccepted(frame.StreamID, accepted) != nil {
		return false
	}
	s.mu.Lock()
	child := s.streams[frame.StreamID]
	s.mu.Unlock()
	if child == nil {
		return false
	}
	child.mu.Lock()
	child.sendCredit = accepted.InitialWindow
	child.mu.Unlock()
	child.acceptOnce.Do(func() { child.accepted <- nil })
	return true
}

func (s *ManagedMultiplexTerminal) handleTypedData(frame protocol.Frame) bool {
	if !s.isTyped() || protocol.ValidateStreamData(frame.StreamID, frame.Payload) != nil {
		return false
	}
	s.mu.Lock()
	child := s.streams[frame.StreamID]
	s.mu.Unlock()
	if child == nil {
		return false
	}
	child.mu.Lock()
	if uint32(len(frame.Payload)) > child.recvCredit || len(frame.Payload) > managedTerminalOutputLimit-child.outputBytes {
		child.mu.Unlock()
		return false
	}
	child.recvCredit -= uint32(len(frame.Payload))
	child.outputQueue = append(child.outputQueue, append([]byte(nil), frame.Payload...))
	child.outputBytes += len(frame.Payload)
	child.mu.Unlock()
	select {
	case child.outputNotify <- struct{}{}:
	default:
	}
	return true
}

func (s *ManagedMultiplexTerminal) handleWindowUpdate(frame protocol.Frame) bool {
	if !s.isTyped() {
		return false
	}
	var update protocol.StreamWindowUpdate
	if protocol.ParseTypedStreamJSON(frame.Payload, &update) != nil || protocol.ValidateStreamWindowUpdate(frame.StreamID, update) != nil {
		return false
	}
	s.mu.Lock()
	child := s.streams[frame.StreamID]
	s.mu.Unlock()
	if child == nil {
		return false
	}
	child.mu.Lock()
	if update.Bytes > protocol.MaxTypedStreamWindow-child.sendCredit {
		child.mu.Unlock()
		return false
	}
	child.sendCredit += update.Bytes
	child.mu.Unlock()
	select {
	case child.creditNotify <- struct{}{}:
	default:
	}
	return true
}

func (s *ManagedMultiplexTerminal) handleStreamClose(frame protocol.Frame) bool {
	if !s.isTyped() {
		return false
	}
	var msg protocol.StreamClose
	if protocol.ParseTypedStreamJSON(frame.Payload, &msg) != nil || protocol.ValidateStreamClose(frame.StreamID, msg) != nil {
		return false
	}
	return s.closeChild(frame.StreamID)
}

func (s *ManagedMultiplexTerminal) handleStreamError(frame protocol.Frame) bool {
	if !s.isTyped() {
		return false
	}
	var msg protocol.StreamError
	if protocol.ParseTypedStreamJSON(frame.Payload, &msg) != nil || protocol.ValidateStreamError(frame.StreamID, msg) != nil {
		return false
	}
	return s.closeChild(frame.StreamID)
}

func (s *ManagedMultiplexTerminal) enqueue(id uint32, data []byte, typed bool) bool {
	s.mu.Lock()
	child := s.streams[id]
	s.mu.Unlock()
	if child == nil {
		return false
	}
	child.mu.Lock()
	defer child.mu.Unlock()
	if len(data) > managedTerminalOutputLimit-child.outputBytes {
		return false
	}
	child.outputQueue = append(child.outputQueue, append([]byte(nil), data...))
	child.outputBytes += len(data)
	select {
	case child.outputNotify <- struct{}{}:
	default:
	}
	return true
}

func (s *ManagedMultiplexTerminal) closeChild(id uint32) bool {
	s.mu.Lock()
	child := s.streams[id]
	if child != nil {
		delete(s.streams, id)
	}
	s.mu.Unlock()
	if child == nil {
		return false
	}
	child.closeOnce.Do(func() {
		close(child.done)
		select {
		case child.outputNotify <- struct{}{}:
		default:
		}
		select {
		case child.creditNotify <- struct{}{}:
		default:
		}
	})
	return true
}

func (s *ManagedMultiplexTerminal) removeChild(id uint32) { _ = s.closeChild(id) }

func (s *ManagedMultiplexTerminal) writeFrame(frame protocol.Frame) error {
	return s.writeFrameContext(context.Background(), frame)
}
func (s *ManagedMultiplexTerminal) writeFrameContext(ctx context.Context, frame protocol.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(managedTerminalWriteTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
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

func (s *ManagedMultiplexTerminal) finish() error {
	var closeErr error
	s.endOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		children := make([]*managedMuxChild, 0, len(s.streams))
		for _, child := range s.streams {
			children = append(children, child)
		}
		s.streams = make(map[uint32]*managedMuxChild)
		s.mu.Unlock()
		for _, child := range children {
			child.acceptOnce.Do(func() { child.accepted <- io.ErrClosedPipe })
			child.closeOnce.Do(func() { close(child.done) })
		}
		_ = s.conn.SetDeadline(time.Now().Add(managedTerminalCloseTimeout))
		closeErr = s.conn.Close()
	})
	return closeErr
}

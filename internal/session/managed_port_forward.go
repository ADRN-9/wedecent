package session

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/portforward"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

const (
	managedPortForwardReceiveWindow uint32 = 256 << 10
	managedPortForwardMaxChildren = 64
	managedPortForwardWriteTimeout = 5 * time.Second
)

type managedPortForwardState struct {
	id     uint32
	parent bool

	mu         sync.Mutex
	readMu     sync.Mutex
	writeMu    sync.Mutex
	sendCredit uint32
	recvCredit uint32
	output     [][]byte
	outputSize int
	notify     chan struct{}
	credit     chan struct{}
	accepted   chan error
	acceptOnce sync.Once
	done       chan struct{}
	closeOnce  sync.Once
	err        error
	remoteEOF  bool
	localEOF   bool
	acceptedOK bool
	closing    bool
	readDead   time.Time
	writeDead  time.Time
}

type ManagedPortForwardSession struct {
	conn *tls.Conn

	writeLock chan struct{}
	mu        sync.Mutex
	states  map[uint32]*managedPortForwardState
	nextID  uint32
	parent  uint32
	alloc   int

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

type ManagedPortForwardConn struct {
	session *ManagedPortForwardSession
	state   *managedPortForwardState
	local   net.Addr
	remote  net.Addr
}

func (c *Client) OpenManagedPortForwardSession(ctx context.Context, peer trust.Peer, auth portforward.Authorization) (*ManagedPortForwardSession, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return nil, errors.New("port forwarding context is required")
		}
		return nil, ctx.Err()
	}
	if c.Identity == nil || c.Trust == nil {
		return nil, errors.New("port forwarding client identity and trust are required")
	}
	if strings.TrimSpace(auth.Signature) == "" || len(auth.Signature) > 256 {
		return nil, portforward.ErrAuthorizationInvalid
	}
	if err := portforward.ValidateClaims(auth.Claims); err != nil {
		return nil, err
	}
	if err := portforward.ValidateRouteAuthorizationBinding(auth); err != nil {
		return nil, err
	}
	inBandAuthorization := c.ForceInBandAuthorization || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(peer.Endpoint)), "wsrelay://")
	if inBandAuthorization {
		grant := strings.TrimSpace(c.ConnectionGrant)
		if grant == "" || len(grant) > 16*1024 || strings.ContainsAny(grant, "\r\n\t ") {
			return nil, errors.New("a valid connection grant is required for this transport")
		}
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
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	capabilities := []protocol.Capability{protocol.CapabilityTypedStreamsV1, protocol.CapabilityPortForwardV1}
	frameType := protocol.TypeOpenSession
	var payload []byte
	if inBandAuthorization {
		frameType = protocol.TypeOpenAuthorizedSession
		payload, err = protocol.JSON(protocol.OpenAuthorizedSession{
			Cols: 80, Rows: 24, ConnectionGrant: strings.TrimSpace(c.ConnectionGrant), Capabilities: capabilities,
		})
	} else {
		payload, err = protocol.JSON(protocol.OpenSession{Cols: 80, Rows: 24, Capabilities: capabilities})
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
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
		return nil, errors.New("port forwarding session was not accepted")
	}
	var accepted protocol.SessionAccepted
	if err := protocol.ParseTypedStreamJSON(first.Payload, &accepted); err != nil ||
		len(accepted.Capabilities) != 2 ||
		accepted.Capabilities[0] != protocol.CapabilityTypedStreamsV1 ||
		accepted.Capabilities[1] != protocol.CapabilityPortForwardV1 {
		_ = conn.Close()
		return nil, errors.New("peer did not negotiate the required port forwarding capability")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	s := &ManagedPortForwardSession{
		conn: conn, states: make(map[uint32]*managedPortForwardState),
		nextID: protocol.MinTypedStreamID, done: make(chan struct{}),
		writeLock: make(chan struct{}, 1),
	}
	go s.monitor()
	if err := s.openParent(ctx, auth); err != nil {
		_ = s.finish()
		return nil, err
	}
	return s, nil
}

func newManagedPortForwardState(id uint32, parent bool) *managedPortForwardState {
	return &managedPortForwardState{
		id: id, parent: parent,
		notify: make(chan struct{}, 1), credit: make(chan struct{}, 1),
		accepted: make(chan error, 1), done: make(chan struct{}),
		recvCredit: managedPortForwardReceiveWindow,
	}
}

func (s *ManagedPortForwardSession) openParent(ctx context.Context, auth portforward.Authorization) error {
	metadata, err := protocol.JSON(portForwardParentOpen{Authorization: auth})
	if err != nil || len(metadata) > protocol.MaxTypedStreamOpenMetadata {
		return portforward.ErrAuthorizationInvalid
	}
	id, state, err := s.reserveState(true)
	if err != nil {
		return err
	}
	payload, err := protocol.JSON(protocol.StreamOpen{
		Kind: protocol.StreamKindPortForwardParent, Metadata: metadata,
		InitialWindow: managedPortForwardReceiveWindow,
	})
	if err != nil {
		s.removeState(id)
		return err
	}
	if err := s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: id, Payload: payload}, time.Time{}); err != nil {
		_ = s.finish()
		return err
	}
	if err := waitManagedPortForwardAcceptance(ctx, s.done, state); err != nil {
		_ = s.finish()
		return err
	}
	s.mu.Lock()
	s.parent = id
	s.mu.Unlock()
	return nil
}

func (s *ManagedPortForwardSession) reserveState(parent bool) (uint32, *managedPortForwardState, error) {
	if s == nil || channelClosed(s.done) {
		return 0, nil, io.ErrClosedPipe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.alloc >= managedMuxMaxAllocated || len(s.states) >= managedPortForwardMaxChildren+1 {
		return 0, nil, errors.New("port forwarding stream limit reached")
	}
	id := s.nextID
	for {
		if id < protocol.MinTypedStreamID {
			id = protocol.MinTypedStreamID
		}
		if _, exists := s.states[id]; !exists {
			break
		}
		id++
	}
	s.nextID = id + 1
	s.alloc++
	state := newManagedPortForwardState(id, parent)
	s.states[id] = state
	return id, state, nil
}

func waitManagedPortForwardAcceptance(ctx context.Context, done <-chan struct{}, state *managedPortForwardState) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return io.ErrClosedPipe
	case err := <-state.accepted:
		return err
	}
}

func (s *ManagedPortForwardSession) OpenChild(ctx context.Context) (net.Conn, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return nil, io.ErrClosedPipe
		}
		return nil, ctx.Err()
	}
	s.mu.Lock()
	parentID := s.parent
	parent := s.states[parentID]
	s.mu.Unlock()
	if parentID < protocol.MinTypedStreamID || parent == nil || channelClosed(parent.done) {
		return nil, io.ErrClosedPipe
	}
	metadata, err := protocol.JSON(portForwardChildOpen{ParentStreamID: parentID})
	if err != nil {
		return nil, err
	}
	id, state, err := s.reserveState(false)
	if err != nil {
		return nil, err
	}
	payload, err := protocol.JSON(protocol.StreamOpen{
		Kind: protocol.StreamKindPortForwardChild, Metadata: metadata,
		InitialWindow: managedPortForwardReceiveWindow,
	})
	if err != nil {
		s.removeState(id)
		return nil, err
	}
	if err := s.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: id, Payload: payload}, time.Time{}); err != nil {
		_ = s.finish()
		return nil, err
	}
	if err := waitManagedPortForwardAcceptance(ctx, s.done, state); err != nil {
		// A sent StreamOpen has ambiguous acceptance on cancellation. Tear down
		// the authenticated parent rather than reuse an unknown StreamID.
		_ = s.finish()
		return nil, err
	}
	return &ManagedPortForwardConn{
		session: s, state: state, local: s.conn.LocalAddr(), remote: s.conn.RemoteAddr(),
	}, nil
}

func (s *ManagedPortForwardSession) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

func (s *ManagedPortForwardSession) monitor() {
	for {
		frame, err := protocol.ReadFrame(s.conn)
		if err != nil {
			_ = s.finish()
			return
		}
		switch frame.Type {
		case protocol.TypePing:
			if err := s.writeFrameContext(context.Background(), protocol.Frame{Type: protocol.TypePong}, time.Time{}); err != nil {
				_ = s.finish()
				return
			}
		case protocol.TypePong:
			continue
		case protocol.TypeStreamAccepted:
			if !s.handleAccepted(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamData:
			if !s.handleData(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamWindowUpdate:
			if !s.handleWindowUpdate(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamHalfClose:
			if !s.handleHalfClose(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamClose:
			if !s.handleClose(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeStreamError:
			if !s.handleError(frame) {
				_ = s.finish()
				return
			}
		case protocol.TypeClose:
			_ = s.finish()
			return
		case protocol.TypeError:
			_ = s.finish()
			return
		default:
			_ = s.finish()
			return
		}
	}
}

func (s *ManagedPortForwardSession) handleAccepted(frame protocol.Frame) bool {
	var accepted protocol.StreamAccepted
	if protocol.ParseTypedStreamJSON(frame.Payload, &accepted) != nil || protocol.ValidateStreamAccepted(frame.StreamID, accepted) != nil {
		return false
	}
	state := s.state(frame.StreamID)
	if state == nil {
		return false
	}
	state.mu.Lock()
	if state.acceptedOK || channelClosed(state.done) {
		state.mu.Unlock()
		return false
	}
	state.acceptedOK = true
	state.sendCredit = accepted.InitialWindow
	state.mu.Unlock()
	state.acceptOnce.Do(func() { state.accepted <- nil })
	return true
}

func (s *ManagedPortForwardSession) handleData(frame protocol.Frame) bool {
	if protocol.ValidateStreamData(frame.StreamID, frame.Payload) != nil {
		return false
	}
	state := s.state(frame.StreamID)
	if state == nil || state.parent {
		return false
	}
	state.mu.Lock()
	if !state.acceptedOK || channelClosed(state.done) || state.remoteEOF ||
		uint32(len(frame.Payload)) > state.recvCredit ||
		len(frame.Payload) > managedTerminalOutputLimit-state.outputSize {
		state.mu.Unlock()
		return false
	}
	state.recvCredit -= uint32(len(frame.Payload))
	state.output = append(state.output, append([]byte(nil), frame.Payload...))
	state.outputSize += len(frame.Payload)
	state.mu.Unlock()
	select {
	case state.notify <- struct{}{}:
	default:
	}
	return true
}

func (s *ManagedPortForwardSession) handleWindowUpdate(frame protocol.Frame) bool {
	var update protocol.StreamWindowUpdate
	if protocol.ParseTypedStreamJSON(frame.Payload, &update) != nil || protocol.ValidateStreamWindowUpdate(frame.StreamID, update) != nil {
		return false
	}
	state := s.state(frame.StreamID)
	if state == nil || state.parent {
		return false
	}
	state.mu.Lock()
	if !state.acceptedOK || update.Bytes > protocol.MaxTypedStreamWindow-state.sendCredit {
		state.mu.Unlock()
		return false
	}
	state.sendCredit += update.Bytes
	state.mu.Unlock()
	select {
	case state.credit <- struct{}{}:
	default:
	}
	return true
}

func (s *ManagedPortForwardSession) handleHalfClose(frame protocol.Frame) bool {
	if protocol.ValidateStreamHalfClose(frame.StreamID, frame.Payload) != nil {
		return false
	}
	state := s.state(frame.StreamID)
	if state == nil || state.parent {
		return false
	}
	state.mu.Lock()
	if !state.acceptedOK || state.remoteEOF || channelClosed(state.done) {
		state.mu.Unlock()
		return false
	}
	state.remoteEOF = true
	state.mu.Unlock()
	select {
	case state.notify <- struct{}{}:
	default:
	}
	return true
}

func (s *ManagedPortForwardSession) handleClose(frame protocol.Frame) bool {
	var message protocol.StreamClose
	if protocol.ParseTypedStreamJSON(frame.Payload, &message) != nil || protocol.ValidateStreamClose(frame.StreamID, message) != nil {
		return false
	}
	state := s.state(frame.StreamID)
	if state == nil {
		return false
	}
	s.closeState(state, nil)
	if state.parent {
		_ = s.finish()
	}
	return true
}

func (s *ManagedPortForwardSession) handleError(frame protocol.Frame) bool {
	var message protocol.StreamError
	if protocol.ParseTypedStreamJSON(frame.Payload, &message) != nil || protocol.ValidateStreamError(frame.StreamID, message) != nil {
		return false
	}
	state := s.state(frame.StreamID)
	if state == nil {
		return false
	}
	err := &ManagedFileStreamError{Code: message.Code, Message: message.Message}
	s.closeState(state, err)
	if state.parent {
		_ = s.finish()
	}
	return true
}

func (s *ManagedPortForwardSession) state(id uint32) *managedPortForwardState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[id]
}

func (s *ManagedPortForwardSession) removeState(id uint32) {
	s.mu.Lock()
	state := s.states[id]
	delete(s.states, id)
	s.mu.Unlock()
	if state != nil {
		s.closeState(state, io.ErrClosedPipe)
	}
}

func (s *ManagedPortForwardSession) closeState(state *managedPortForwardState, err error) {
	state.closeOnce.Do(func() {
		state.mu.Lock()
		state.err = err
		accepted := state.acceptedOK
		state.mu.Unlock()
		if !accepted {
			acceptErr := err
			if acceptErr == nil {
				acceptErr = io.ErrClosedPipe
			}
			state.acceptOnce.Do(func() { state.accepted <- acceptErr })
		}
		s.mu.Lock()
		if s.states[state.id] == state {
			delete(s.states, state.id)
		}
		s.mu.Unlock()
		close(state.done)
		select {
		case state.notify <- struct{}{}:
		default:
		}
		select {
		case state.credit <- struct{}{}:
		default:
		}
	})
}

func (s *ManagedPortForwardSession) writeFrameContext(ctx context.Context, frame protocol.Frame, deadline time.Time) error {
	if s == nil || s.conn == nil {
		return io.ErrClosedPipe
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return io.ErrClosedPipe
	case s.writeLock <- struct{}{}:
	}
	defer func() { <-s.writeLock }()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.done:
		return io.ErrClosedPipe
	default:
	}

	writeDeadline := time.Now().Add(managedPortForwardWriteTimeout)
	if !deadline.IsZero() && deadline.Before(writeDeadline) {
		writeDeadline = deadline
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(writeDeadline) {
		writeDeadline = ctxDeadline
	}
	if err := s.conn.SetWriteDeadline(writeDeadline); err != nil {
		_ = s.finish()
		return err
	}
	stopCancel := context.AfterFunc(ctx, func() {
		// A canceled write may have emitted a partial frame; discard the parent.
		_ = s.conn.NetConn().Close()
	})
	writeErr := protocol.WriteFrame(s.conn, frame)
	stopCancel()
	resetErr := s.conn.SetWriteDeadline(time.Time{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		finishErr := s.finish()
		return errors.Join(ctxErr, writeErr, resetErr, finishErr)
	}
	if writeErr != nil || resetErr != nil {
		finishErr := s.finish()
		return errors.Join(writeErr, resetErr, finishErr)
	}
	return nil
}

func (s *ManagedPortForwardSession) finish() error {
	s.closeOnce.Do(func() {
		close(s.done)
		// Close the parent transport before waiting for child state cleanup.
		connErr := s.conn.NetConn().Close()
		s.mu.Lock()
		states := make([]*managedPortForwardState, 0, len(s.states))
		for _, state := range s.states {
			states = append(states, state)
		}
		s.states = make(map[uint32]*managedPortForwardState)
		s.mu.Unlock()
		for _, state := range states {
			state.acceptOnce.Do(func() { state.accepted <- io.ErrClosedPipe })
			s.closeState(state, io.ErrClosedPipe)
		}
		s.closeErr = connErr
	})
	return s.closeErr
}

func (s *ManagedPortForwardSession) Close() error {
	if s == nil {
		return nil
	}
	// Local shutdown is authoritative; a remote close frame is best-effort
	// protocol hygiene and must never gate transport closure.
	return s.finish()
}

func (c *ManagedPortForwardConn) Read(p []byte) (int, error) {
	if c == nil || c.session == nil || c.state == nil {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	state := c.state
	state.readMu.Lock()
	defer state.readMu.Unlock()
	for {
		state.mu.Lock()
		if len(state.output) > 0 {
			chunk := state.output[0]
			n := copy(p, chunk)
			if n == len(chunk) {
				state.output[0] = nil
				state.output = state.output[1:]
			} else {
				state.output[0] = chunk[n:]
			}
			state.outputSize -= n
			state.recvCredit += uint32(n)
			state.mu.Unlock()
			payload, _ := protocol.JSON(protocol.StreamWindowUpdate{Bytes: uint32(n)})
			if err := c.session.writeFrameContext(context.Background(), protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: state.id, Payload: payload}, time.Time{}); err != nil {
				_ = c.session.finish()
				return n, err
			}
			return n, nil
		}
		if state.remoteEOF {
			state.mu.Unlock()
			return 0, io.EOF
		}
		if state.err != nil {
			err := state.err
			state.mu.Unlock()
			return 0, err
		}
		if channelClosed(state.done) || channelClosed(c.session.done) {
			state.mu.Unlock()
			return 0, io.ErrClosedPipe
		}
		deadline := state.readDead
		state.mu.Unlock()
		if err := waitPortForwardSignal(state.notify, state.done, c.session.done, deadline); err != nil {
			return 0, err
		}
	}
}

func (c *ManagedPortForwardConn) Write(p []byte) (int, error) {
	if c == nil || c.session == nil || c.state == nil {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	state := c.state
	state.writeMu.Lock()
	defer state.writeMu.Unlock()
	written := 0
	for written < len(p) {
		var count int
		for count == 0 {
			state.mu.Lock()
			if state.localEOF || state.err != nil || channelClosed(state.done) || channelClosed(c.session.done) {
				err := state.err
				state.mu.Unlock()
				if err != nil {
					return written, err
				}
				return written, io.ErrClosedPipe
			}
			if state.sendCredit > 0 {
				count = len(p) - written
				if count > protocol.MaxTypedStreamChunk {
					count = protocol.MaxTypedStreamChunk
				}
				if uint32(count) > state.sendCredit {
					count = int(state.sendCredit)
				}
				state.sendCredit -= uint32(count)
			}
			deadline := state.writeDead
			state.mu.Unlock()
			if count == 0 {
				if err := waitPortForwardSignal(state.credit, state.done, c.session.done, deadline); err != nil {
					return written, err
				}
			}
		}
		state.mu.Lock()
		deadline := state.writeDead
		state.mu.Unlock()
		err := c.session.writeFrameContext(context.Background(), protocol.Frame{
			Type: protocol.TypeStreamData, StreamID: state.id, Payload: append([]byte(nil), p[written:written+count]...),
		}, deadline)
		if err != nil {
			_ = c.session.finish()
			return written, err
		}
		written += count
	}
	return written, nil
}

func (c *ManagedPortForwardConn) CloseWrite() error {
	if c == nil || c.session == nil || c.state == nil {
		return io.ErrClosedPipe
	}
	state := c.state
	state.mu.Lock()
	if state.localEOF {
		state.mu.Unlock()
		return nil
	}
	if channelClosed(state.done) {
		state.mu.Unlock()
		return io.ErrClosedPipe
	}
	state.localEOF = true
	state.mu.Unlock()
	if err := c.session.writeFrameContext(context.Background(), protocol.Frame{Type: protocol.TypeStreamHalfClose, StreamID: state.id}, time.Time{}); err != nil {
		_ = c.session.finish()
		return err
	}
	return nil
}

func (c *ManagedPortForwardConn) Close() error {
	if c == nil || c.session == nil || c.state == nil {
		return nil
	}
	state := c.state
	state.mu.Lock()
	if state.closing || channelClosed(state.done) {
		state.mu.Unlock()
		return nil
	}
	state.closing = true
	state.mu.Unlock()
	payload, _ := protocol.JSON(protocol.StreamClose{Reason: "client_close"})
	if err := c.session.writeFrameContext(context.Background(), protocol.Frame{Type: protocol.TypeStreamClose, StreamID: state.id, Payload: payload}, time.Time{}); err != nil {
		_ = c.session.finish()
		return err
	}
	select {
	case <-state.done:
		return state.err
	case <-c.session.done:
		return io.ErrClosedPipe
	case <-time.After(managedTerminalCloseTimeout):
		_ = c.session.finish()
		return errors.New("port forwarding child close acknowledgement timed out")
	}
}

func (c *ManagedPortForwardConn) LocalAddr() net.Addr {
	if c == nil { return nil }
	return c.local
}
func (c *ManagedPortForwardConn) RemoteAddr() net.Addr {
	if c == nil { return nil }
	return c.remote
}
func (c *ManagedPortForwardConn) SetDeadline(t time.Time) error {
	if c == nil || c.state == nil { return io.ErrClosedPipe }
	c.state.mu.Lock()
	c.state.readDead, c.state.writeDead = t, t
	c.state.mu.Unlock()
	return nil
}
func (c *ManagedPortForwardConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.state == nil { return io.ErrClosedPipe }
	c.state.mu.Lock()
	c.state.readDead = t
	c.state.mu.Unlock()
	return nil
}
func (c *ManagedPortForwardConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.state == nil { return io.ErrClosedPipe }
	c.state.mu.Lock()
	c.state.writeDead = t
	c.state.mu.Unlock()
	return nil
}

func (state *managedPortForwardState) deadlineRead() time.Time {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.readDead
}

func waitPortForwardSignal(signal, stateDone, sessionDone <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-signal:
			return nil
		case <-stateDone:
			return io.ErrClosedPipe
		case <-sessionDone:
			return io.ErrClosedPipe
		}
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-signal:
		return nil
	case <-stateDone:
		return io.ErrClosedPipe
	case <-sessionDone:
		return io.ErrClosedPipe
	case <-timer.C:
		return timeoutError{}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Conn = (*ManagedPortForwardConn)(nil)

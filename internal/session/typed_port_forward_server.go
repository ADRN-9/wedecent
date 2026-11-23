package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/portforward"
	"wedecent.com/wedecent/internal/protocol"
)

const portForwardReceiveWindow uint32 = 256 << 10

type portForwardParentOpen struct {
	Authorization portforward.Authorization `json:"authorization"`
}

type portForwardChildOpen struct {
	ParentStreamID uint32 `json:"parent_stream_id"`
}

type typedPortForwardParent struct {
	id        uint32
	acceptMu  sync.Mutex
	session   *portforward.DestinationSession
	children  map[uint32]*typedPortForwardChild
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

type typedPortForwardChild struct {
	id     uint32
	parent *typedPortForwardParent
	conn   net.Conn

	mu          sync.Mutex
	sendCredit  typedStreamCredit
	recvCredit  typedStreamCredit
	creditCh    chan struct{}
	writeCh     chan struct{}
	writeBuffer []byte
	done        <-chan struct{}
	cancel      func()
	doneOnce    sync.Once
	closeOnce   sync.Once
	closeDone   chan struct{}
	writeMu     sync.Mutex
	sendMu      sync.Mutex
	closing     bool
	inputEOF    bool
	closeErr    error
}

type typedPortForwardServer struct {
	ctx      context.Context
	localID  mesh.DeviceID
	peerID   mesh.DeviceID
	routerID mesh.DeviceID
	runtime  *PortForwardRuntime
	registry *typedParentStreamRegistry
	write    typedTerminalFrameWriter
	cleanupTimeout time.Duration

	mu       sync.Mutex
	parents  map[uint32]*typedPortForwardParent
	children map[uint32]*typedPortForwardChild
	closed   bool
	closeErr error
}

func newTypedPortForwardServer(
	ctx context.Context,
	localID, peerID, routerID string,
	runtime *PortForwardRuntime,
	registry *typedParentStreamRegistry,
	write typedTerminalFrameWriter,
) *typedPortForwardServer {
	return &typedPortForwardServer{
		ctx:      ctx,
		localID:  mesh.DeviceID(localID),
		peerID:   mesh.DeviceID(peerID),
		routerID: mesh.DeviceID(routerID),
		runtime:  runtime,
		registry: registry,
		write:    write,
		parents:  make(map[uint32]*typedPortForwardParent),
		children: make(map[uint32]*typedPortForwardChild),
	}
}

func (s *typedPortForwardServer) Handle(ctx context.Context, frame protocol.Frame) error {
	switch frame.Type {
	case protocol.TypeStreamOpen:
		var open protocol.StreamOpen
		if err := protocol.ParseTypedStreamJSON(frame.Payload, &open); err != nil {
			return fmt.Errorf("%w: malformed port forwarding stream open", errTypedStreamProtocol)
		}
		switch open.Kind {
		case protocol.StreamKindPortForwardParent:
			return s.openParent(ctx, frame, open)
		case protocol.StreamKindPortForwardChild:
			return s.openChild(ctx, frame, open)
		default:
			return fmt.Errorf("%w: unsupported port forwarding stream kind", errTypedStreamProtocol)
		}
	case protocol.TypeStreamData:
		return s.data(frame)
	case protocol.TypeStreamWindowUpdate:
		return s.windowUpdate(frame)
	case protocol.TypeStreamHalfClose:
		return s.halfClose(frame)
	case protocol.TypeStreamClose:
		return s.peerClose(frame)
	case protocol.TypeStreamError:
		return s.peerError(frame)
	default:
		return fmt.Errorf("%w: unsupported port forwarding frame type", errTypedStreamProtocol)
	}
}

func (s *typedPortForwardServer) openParent(ctx context.Context, frame protocol.Frame, open protocol.StreamOpen) error {
	if err := protocol.ValidatePortForwardParentOpen(frame.StreamID, open); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	var metadata portForwardParentOpen
	if err := protocol.ParseTypedStreamJSON(open.Metadata, &metadata); err != nil || metadata.Authorization.Signature == "" {
		return s.rejectOpen(frame.StreamID, protocol.StreamKindPortForwardParent, "invalid_forwarding_authorization")
	}
	if err := s.registry.reserve(frame.StreamID, protocol.StreamKindPortForwardParent); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	destination, err := s.runtime.OpenDestinationSession(ctx, s.localID, s.peerID, s.routerID, metadata.Authorization)
	if err != nil {
		_ = s.registry.close(frame.StreamID, protocol.StreamKindPortForwardParent)
		return s.sendStreamError(frame.StreamID, "forwarding_authorization_denied", "forwarding authorization was rejected")
	}
	parent := &typedPortForwardParent{
		id:       frame.StreamID,
		session:  destination,
		children: make(map[uint32]*typedPortForwardChild),
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		_ = destination.Close()
		_ = s.registry.close(frame.StreamID, protocol.StreamKindPortForwardParent)
		return s.sendStreamError(frame.StreamID, "parent_session_closed", "parent session is closed")
	}
	s.parents[frame.StreamID] = parent
	s.mu.Unlock()
	accepted, err := s.publishParentAcceptance(parent)
	if err != nil {
		_ = s.closeParent(frame.StreamID, "transport_write_failed", false)
		return err
	}
	if !accepted {
		_ = s.registry.close(frame.StreamID, protocol.StreamKindPortForwardParent)
		return nil
	}
	s.mu.Lock()
	attached := !s.closed && !parent.closed && s.parents[frame.StreamID] == parent
	if attached {
		go s.watchDestinationParent(parent)
	}
	s.mu.Unlock()
	return nil
}

func (s *typedPortForwardServer) publishParentAcceptance(parent *typedPortForwardParent) (bool, error) {
	parent.acceptMu.Lock()
	defer parent.acceptMu.Unlock()
	s.mu.Lock()
	attached := !s.closed && !parent.closed && s.parents[parent.id] == parent
	s.mu.Unlock()
	if !attached {
		return false, nil
	}
	if err := s.registry.accept(parent.id, protocol.StreamKindPortForwardParent); err != nil {
		return false, err
	}
	s.mu.Lock()
	attached = !s.closed && !parent.closed && s.parents[parent.id] == parent
	s.mu.Unlock()
	if !attached {
		return false, nil
	}
	if err := s.sendAccepted(parent.id); err != nil {
		return true, err
	}
	return true, nil
}

// publishChildAcceptance holds the parent gate through the wire ACK. Parent
// closure cannot detach the stream until this publication has completed.
func (s *typedPortForwardServer) publishChildAcceptance(parent *typedPortForwardParent, child *typedPortForwardChild) (bool, error) {
	parent.acceptMu.Lock()
	defer parent.acceptMu.Unlock()
	s.mu.Lock()
	attached := !s.closed && !parent.closed && s.parents[parent.id] == parent && !child.isClosed()
	if attached {
		s.children[child.id] = child
		parent.children[child.id] = child
	}
	s.mu.Unlock()
	if !attached {
		return false, nil
	}
	if err := s.registry.accept(child.id, protocol.StreamKindPortForwardChild); err != nil {
		s.detachChild(child.id)
		return false, err
	}
	child.sendMu.Lock()
	s.mu.Lock()
	attached = !s.closed && !parent.closed &&
		s.parents[parent.id] == parent && s.children[child.id] == child &&
		!child.isClosed()
	s.mu.Unlock()
	if !attached {
		child.sendMu.Unlock()
		s.detachChild(child.id)
		return false, nil
	}
	err := s.sendAccepted(child.id)
	child.sendMu.Unlock()
	if err != nil {
		s.detachChild(child.id)
		return false, err
	}
	return true, nil
}

func (s *typedPortForwardServer) watchDestinationParent(parent *typedPortForwardParent) {
	select {
	case <-s.ctx.Done():
		return
	case <-parent.session.Done():
	}
	s.mu.Lock()
	closed := s.closed || parent.closed
	s.mu.Unlock()
	if !closed {
		_ = s.closeParent(parent.id, "destination_session_ended", false)
		if s.ctx.Err() == nil {
			_ = s.sendStreamError(parent.id, "forwarding_session_ended", "forwarding authorization is no longer active")
		}
	}
}

func (s *typedPortForwardServer) openChild(ctx context.Context, frame protocol.Frame, open protocol.StreamOpen) error {
	if err := protocol.ValidatePortForwardChildOpen(frame.StreamID, open); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	var metadata portForwardChildOpen
	if err := protocol.ParseTypedStreamJSON(open.Metadata, &metadata); err != nil || metadata.ParentStreamID < protocol.MinTypedStreamID {
		return s.rejectOpen(frame.StreamID, protocol.StreamKindPortForwardChild, "invalid_parent_stream")
	}
	if err := s.registry.reserve(frame.StreamID, protocol.StreamKindPortForwardChild); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	s.mu.Lock()
	parent := s.parents[metadata.ParentStreamID]
	if s.closed || parent == nil || parent.closed {
		s.mu.Unlock()
		_ = s.registry.close(frame.StreamID, protocol.StreamKindPortForwardChild)
		return s.sendStreamError(frame.StreamID, "parent_stream_unavailable", "forwarding parent stream is unavailable")
	}
	s.mu.Unlock()

	conn, err := parent.session.OpenChild(ctx)
	if err != nil {
		_ = s.registry.close(frame.StreamID, protocol.StreamKindPortForwardChild)
		s.mu.Lock()
		attached := !s.closed && !parent.closed && s.parents[parent.id] == parent
		s.mu.Unlock()
		if !attached {
			return nil
		}
		return s.sendStreamError(frame.StreamID, "destination_connection_denied", "destination connection could not be opened")
	}
	sendCredit, err := newTypedStreamCredit(open.InitialWindow)
	if err != nil {
		_ = conn.Close()
		_ = s.registry.close(frame.StreamID, protocol.StreamKindPortForwardChild)
		return fmt.Errorf("%w: invalid child send window", errTypedStreamProtocol)
	}
	recvCredit, err := newTypedStreamCredit(portForwardReceiveWindow)
	if err != nil {
		_ = conn.Close()
		_ = s.registry.close(frame.StreamID, protocol.StreamKindPortForwardChild)
		return err
	}
	doneCh := make(chan struct{})
	var done <-chan struct{} = doneCh
	cancel := func() { close(doneCh) }
	if lifecycle, ok := conn.(interface {
		Done() <-chan struct{}
		Cancel()
	}); ok {
		done = lifecycle.Done()
		cancel = lifecycle.Cancel
	}
	child := &typedPortForwardChild{
		id: frame.StreamID, parent: parent, conn: conn,
		sendCredit: sendCredit, recvCredit: recvCredit,
		creditCh: make(chan struct{}, 1), writeCh: make(chan struct{}, 1),
		done: done, cancel: cancel,
	}
	accepted, err := s.publishChildAcceptance(parent, child)
	if err != nil {
		_ = s.closeChild(child.id, "registry_accept_failed", false)
		return err
	}
	if !accepted {
		child.signalClose()
		_ = s.registry.close(frame.StreamID, protocol.StreamKindPortForwardChild)
		return nil
	}

	// Parent closure may race with the acceptance write. Never start workers
	// after the parent has detached this child.
	s.mu.Lock()
	attached := !s.closed && !parent.closed &&
		s.parents[parent.id] == parent && s.children[child.id] == child &&
		!child.isClosed()
	if attached {
		go s.forwardInput(child)
		go s.forwardOutput(child)
	}
	s.mu.Unlock()
	return nil
}

func (child *typedPortForwardChild) isClosed() bool {
	if child == nil {
		return true
	}
	select {
	case <-child.done:
		return true
	default:
	}
	child.mu.Lock()
	closing := child.closing
	child.mu.Unlock()
	return closing
}

func (child *typedPortForwardChild) signalClose() {
	if child == nil {
		return
	}
	child.mu.Lock()
	child.closing = true
	for i := range child.writeBuffer {
		child.writeBuffer[i] = 0
	}
	child.writeBuffer = nil
	child.mu.Unlock()
	child.doneOnce.Do(child.cancel)
}

func (s *typedPortForwardServer) data(frame protocol.Frame) error {
	if err := protocol.ValidateStreamData(frame.StreamID, frame.Payload); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child := s.child(frame.StreamID)
	if child == nil {
		return fmt.Errorf("%w: forwarding child is not open", errTypedStreamProtocol)
	}
	child.mu.Lock()
	if child.closing || child.inputEOF || channelClosed(child.done) {
		child.mu.Unlock()
		return fmt.Errorf("%w: forwarding child is closed", errTypedStreamProtocol)
	}
	if err := child.recvCredit.consume(uint32(len(frame.Payload))); err != nil {
		child.mu.Unlock()
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	if len(child.writeBuffer)+len(frame.Payload) > int(portForwardReceiveWindow) {
		child.mu.Unlock()
		return fmt.Errorf("%w: forwarding destination queue exceeded its receive window", errTypedStreamProtocol)
	}
	child.writeBuffer = append(child.writeBuffer, frame.Payload...)
	child.mu.Unlock()
	select {
	case child.writeCh <- struct{}{}:
	default:
	}
	return nil
}

func (s *typedPortForwardServer) forwardInput(child *typedPortForwardChild) {
	for {
		if child.isClosed() || s.ctx.Err() != nil {
			return
		}
		child.mu.Lock()
		if child.closing || channelClosed(child.done) {
			child.writeBuffer = nil
			child.mu.Unlock()
			return
		}
		count := len(child.writeBuffer)
		if count > protocol.MaxTypedStreamChunk {
			count = protocol.MaxTypedStreamChunk
		}
		var data []byte
		if count > 0 {
			data = append([]byte(nil), child.writeBuffer[:count]...)
			copy(child.writeBuffer, child.writeBuffer[count:])
			child.writeBuffer = child.writeBuffer[:len(child.writeBuffer)-count]
		}
		child.mu.Unlock()

		if len(data) == 0 {
			child.mu.Lock()
			inputEOF := child.inputEOF
			child.mu.Unlock()
			if inputEOF {
				child.writeMu.Lock()
				if child.isClosed() || s.ctx.Err() != nil {
					child.writeMu.Unlock()
					return
				}
				writer, ok := child.conn.(interface{ CloseWrite() error })
				var closeErr error
				if !ok {
					closeErr = portforward.ErrHalfCloseUnsupported
				} else {
					closeErr = writer.CloseWrite()
				}
				child.writeMu.Unlock()
				if closeErr != nil && !child.isClosed() {
					code := "half_close_failed"
					message := "destination TCP half-close failed"
					if errors.Is(closeErr, portforward.ErrHalfCloseUnsupported) {
						code = "half_close_unsupported"
						message = "destination transport does not support TCP half-close"
					}
					_ = s.writeChildError(child, code, message)
					_ = s.closeChild(child.id, code, false)
				}
				return
			}
			select {
			case <-s.ctx.Done():
				return
			case <-child.done:
				return
			case <-child.writeCh:
				continue
			}
		}

		for remaining := data; len(remaining) > 0; {
			child.writeMu.Lock()
			if child.isClosed() || s.ctx.Err() != nil {
				child.writeMu.Unlock()
				return
			}
			n, err := child.conn.Write(remaining)
			child.writeMu.Unlock()
			if err != nil || n <= 0 {
				if err == nil {
					err = io.ErrShortWrite
				}
				if !child.isClosed() {
					_ = s.closeChild(child.id, "destination_write_failed", false)
					if s.ctx.Err() == nil {
						_ = s.writeChildError(child, "destination_write_failed", "destination connection write failed")
					}
				}
				return
			}
			remaining = remaining[n:]
		}

		if child.isClosed() || s.ctx.Err() != nil {
			return
		}
		child.mu.Lock()
		err := child.recvCredit.add(uint32(len(data)))
		child.mu.Unlock()
		if err != nil {
			_ = s.closeChild(child.id, "credit_accounting_failed", false)
			return
		}
		payload, err := protocol.JSON(protocol.StreamWindowUpdate{Bytes: uint32(len(data))})
		if err != nil {
			_ = s.closeChild(child.id, "window_update_encode_failed", false)
			return
		}
		if child.isClosed() || s.ctx.Err() != nil {
			return
		}
		if err := s.writeChildFrame(child, protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: child.id, Payload: payload}); err != nil {
			_ = s.closeChild(child.id, "transport_write_failed", false)
			return
		}
	}
}

func (s *typedPortForwardServer) windowUpdate(frame protocol.Frame) error {
	var update protocol.StreamWindowUpdate
	if err := protocol.ParseTypedStreamJSON(frame.Payload, &update); err != nil || protocol.ValidateStreamWindowUpdate(frame.StreamID, update) != nil {
		return fmt.Errorf("%w: malformed forwarding window update", errTypedStreamProtocol)
	}
	child := s.child(frame.StreamID)
	if child == nil {
		return fmt.Errorf("%w: forwarding child is not open", errTypedStreamProtocol)
	}
	if child.isClosed() {
		return fmt.Errorf("%w: forwarding child is closed", errTypedStreamProtocol)
	}
	child.mu.Lock()
	err := child.sendCredit.add(update.Bytes)
	child.mu.Unlock()
	if err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	select {
	case child.creditCh <- struct{}{}:
	default:
	}
	return nil
}

func (s *typedPortForwardServer) halfClose(frame protocol.Frame) error {
	if err := protocol.ValidateStreamHalfClose(frame.StreamID, frame.Payload); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child := s.child(frame.StreamID)
	if child == nil {
		return fmt.Errorf("%w: forwarding child is not open", errTypedStreamProtocol)
	}
	child.mu.Lock()
	if child.closing || channelClosed(child.done) {
		child.mu.Unlock()
		return fmt.Errorf("%w: forwarding child is closed", errTypedStreamProtocol)
	}
	child.inputEOF = true
	child.mu.Unlock()
	select {
	case child.writeCh <- struct{}{}:
	default:
	}
	return nil
}

func (s *typedPortForwardServer) peerClose(frame protocol.Frame) error {
	var message protocol.StreamClose
	if err := protocol.ParseTypedStreamJSON(frame.Payload, &message); err != nil || protocol.ValidateStreamClose(frame.StreamID, message) != nil {
		return fmt.Errorf("%w: malformed forwarding stream close", errTypedStreamProtocol)
	}
	kind, ok := s.registry.kind(frame.StreamID)
	if !ok {
		return fmt.Errorf("%w: forwarding stream is not open", errTypedStreamProtocol)
	}
	switch kind {
	case protocol.StreamKindPortForwardChild:
		return s.closeChild(frame.StreamID, "peer_close", true)
	case protocol.StreamKindPortForwardParent:
		return s.closeParent(frame.StreamID, "peer_close", true)
	default:
		return fmt.Errorf("%w: invalid forwarding stream kind", errTypedStreamProtocol)
	}
}

func (s *typedPortForwardServer) peerError(frame protocol.Frame) error {
	var message protocol.StreamError
	if err := protocol.ParseTypedStreamJSON(frame.Payload, &message); err != nil || protocol.ValidateStreamError(frame.StreamID, message) != nil {
		return fmt.Errorf("%w: malformed forwarding stream error", errTypedStreamProtocol)
	}
	kind, ok := s.registry.kind(frame.StreamID)
	if !ok {
		return fmt.Errorf("%w: forwarding stream is not open", errTypedStreamProtocol)
	}
	switch kind {
	case protocol.StreamKindPortForwardChild:
		return s.closeChild(frame.StreamID, "peer_error", false)
	case protocol.StreamKindPortForwardParent:
		return s.closeParent(frame.StreamID, "peer_error", false)
	default:
		return fmt.Errorf("%w: invalid forwarding stream kind", errTypedStreamProtocol)
	}
}

func (s *typedPortForwardServer) forwardOutput(child *typedPortForwardChild) {
	buffer := make([]byte, protocol.MaxTypedStreamChunk)
	for {
		if child.isClosed() || s.ctx.Err() != nil {
			return
		}
		n, readErr := child.conn.Read(buffer)
		if child.isClosed() || s.ctx.Err() != nil {
			return
		}
		if n > 0 {
			if err := s.sendData(child, buffer[:n]); err != nil {
				if !child.isClosed() {
					_ = s.closeChild(child.id, "transport_write_failed", false)
				}
				return
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if !child.isClosed() && s.ctx.Err() == nil {
					if err := s.writeChildFrame(child, protocol.Frame{Type: protocol.TypeStreamHalfClose, StreamID: child.id}); err != nil {
						_ = s.closeChild(child.id, "transport_write_failed", false)
					}
				}
				return
			}
			if !errors.Is(readErr, net.ErrClosed) && !errors.Is(readErr, io.ErrClosedPipe) && !child.isClosed() {
				_ = s.writeChildError(child, "destination_read_failed", "destination connection read failed")
			}
			if !child.isClosed() {
				_ = s.closeChild(child.id, "destination_read_failed", false)
			}
			return
		}
		if n == 0 {
			if !child.isClosed() {
				_ = s.closeChild(child.id, "destination_read_failed", false)
			}
			return
		}
	}
}

func (s *typedPortForwardServer) sendData(child *typedPortForwardChild, data []byte) error {
	for offset := 0; offset < len(data); {
		if child.isClosed() || s.ctx.Err() != nil {
			return io.ErrClosedPipe
		}
		var count int
		for count == 0 {
			child.mu.Lock()
			if child.closing || channelClosed(child.done) {
				child.mu.Unlock()
				return io.ErrClosedPipe
			}
			available := child.sendCredit.available()
			if available > 0 {
				count = len(data) - offset
				if count > protocol.MaxTypedStreamChunk {
					count = protocol.MaxTypedStreamChunk
				}
				if uint32(count) > available {
					count = int(available)
				}
				if err := child.sendCredit.consume(uint32(count)); err != nil {
					child.mu.Unlock()
					return err
				}
			}
			child.mu.Unlock()
			if count == 0 {
				select {
				case <-s.ctx.Done():
					return s.ctx.Err()
				case <-child.done:
					return io.ErrClosedPipe
				case <-child.creditCh:
				}
			}
		}
		if child.isClosed() || s.ctx.Err() != nil {
			return io.ErrClosedPipe
		}
		err := s.writeChildFrame(child, protocol.Frame{
			Type: protocol.TypeStreamData, StreamID: child.id,
			Payload: append([]byte(nil), data[offset:offset+count]...),
		})
		if err != nil {
			return err
		}
		offset += count
	}
	return nil
}

func (s *typedPortForwardServer) writeChildFrame(child *typedPortForwardChild, frame protocol.Frame) error {
	if child == nil {
		return io.ErrClosedPipe
	}
	child.sendMu.Lock()
	defer child.sendMu.Unlock()
	if child.isClosed() || s.ctx.Err() != nil {
		return io.ErrClosedPipe
	}
	return s.write(frame)
}

func (s *typedPortForwardServer) writeChildError(child *typedPortForwardChild, code, message string) error {
	payload, err := protocol.JSON(protocol.StreamError{Code: code, Message: message})
	if err != nil {
		return err
	}
	return s.writeChildFrame(child, protocol.Frame{Type: protocol.TypeStreamError, StreamID: child.id, Payload: payload})
}

func (s *typedPortForwardServer) sendAccepted(streamID uint32) error {
	payload, err := protocol.JSON(protocol.StreamAccepted{InitialWindow: portForwardReceiveWindow})
	if err != nil {
		return err
	}
	return s.write(protocol.Frame{Type: protocol.TypeStreamAccepted, StreamID: streamID, Payload: payload})
}

func (s *typedPortForwardServer) sendStreamError(streamID uint32, code, message string) error {
	payload, err := protocol.JSON(protocol.StreamError{Code: code, Message: message})
	if err != nil {
		return err
	}
	return s.write(protocol.Frame{Type: protocol.TypeStreamError, StreamID: streamID, Payload: payload})
}

func (s *typedPortForwardServer) rejectOpen(streamID uint32, kind protocol.StreamKind, code string) error {
	if err := s.registry.reserve(streamID, kind); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	_ = s.registry.close(streamID, kind)
	return s.sendStreamError(streamID, code, "invalid port forwarding stream open")
}

func (s *typedPortForwardServer) child(streamID uint32) *typedPortForwardChild {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.children[streamID]
}

func (s *typedPortForwardServer) closeChild(streamID uint32, reason string, acknowledge bool) error {
	s.mu.Lock()
	child := s.children[streamID]
	s.mu.Unlock()
	if child == nil {
		return nil
	}
	child.sendMu.Lock()
	s.mu.Lock()
	if s.children[streamID] == child {
		delete(s.children, streamID)
		delete(child.parent.children, streamID)
	} else {
		s.mu.Unlock()
		child.sendMu.Unlock()
		return nil
	}
	s.mu.Unlock()
	child.signalClose()
	child.sendMu.Unlock()
	child.closeOnce.Do(func() {
		child.closeDone = make(chan struct{})
		go func() {
			child.closeErr = child.conn.Close()
			close(child.closeDone)
		}()
	})
	timer := time.NewTimer(s.childCleanupTimeout())
	var closeErr error
	select {
	case <-child.closeDone:
		closeErr = child.closeErr
	case <-timer.C:
		closeErr = portforward.ErrDestinationCleanupIncomplete
	}
	timer.Stop()
	_ = s.registry.close(streamID, protocol.StreamKindPortForwardChild)
	if acknowledge {
		payload, _ := protocol.JSON(protocol.StreamClose{Reason: "peer_close"})
		closeErr = errors.Join(closeErr, s.write(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: streamID, Payload: payload}))
	}
	if closeErr != nil {
		s.mu.Lock()
		s.closeErr = errors.Join(s.closeErr, closeErr)
		s.mu.Unlock()
	}
	return closeErr
}

func (s *typedPortForwardServer) detachChild(streamID uint32) {
	s.mu.Lock()
	child := s.children[streamID]
	s.mu.Unlock()
	if child == nil {
		return
	}
	child.sendMu.Lock()
	s.mu.Lock()
	if s.children[streamID] == child {
		delete(s.children, streamID)
		delete(child.parent.children, streamID)
	}
	s.mu.Unlock()
	child.signalClose()
	child.sendMu.Unlock()
	// DestinationSession owns the underlying child connection and cleanup.
	_ = s.registry.close(streamID, protocol.StreamKindPortForwardChild)
}

func (s *typedPortForwardServer) markParentClosed(parent *typedPortForwardParent) bool {
	if parent == nil {
		return false
	}
	parent.acceptMu.Lock()
	defer parent.acceptMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.parents[parent.id] != parent {
		return false
	}
	parent.closed = true
	for _, child := range parent.children {
		child.signalClose()
	}
	return true
}

func (s *typedPortForwardServer) childCleanupTimeout() time.Duration {
	if s != nil && s.cleanupTimeout > 0 {
		return s.cleanupTimeout
	}
	return 5 * time.Second
}

func (s *typedPortForwardServer) closeParent(streamID uint32, reason string, acknowledge bool) error {
	s.mu.Lock()
	parent := s.parents[streamID]
	s.mu.Unlock()
	if parent != nil {
		s.markParentClosed(parent)
	}
	if parent == nil {
		return nil
	}

	parent.closeOnce.Do(func() {
		var errs []error
		// Child cancellation is signalled above before any network cleanup.
		if err := parent.session.Close(); err != nil {
			errs = append(errs, err)
		}
		s.mu.Lock()
		children := make([]uint32, 0, len(parent.children))
		for id := range parent.children {
			children = append(children, id)
		}
		s.mu.Unlock()
		for _, childID := range children {
			s.detachChild(childID)
		}
		_ = s.registry.close(streamID, protocol.StreamKindPortForwardParent)
		if acknowledge {
			payload, _ := protocol.JSON(protocol.StreamClose{Reason: "peer_close"})
			if err := s.write(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: streamID, Payload: payload}); err != nil {
				errs = append(errs, err)
			}
		}
		parent.closeErr = errors.Join(errs...)
		s.mu.Lock()
		if s.parents[streamID] == parent {
			delete(s.parents, streamID)
		}
		if parent.closeErr != nil {
			s.closeErr = errors.Join(s.closeErr, parent.closeErr)
		}
		s.mu.Unlock()
	})
	return parent.closeErr
}

func (s *typedPortForwardServer) CloseAll() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	parents := make([]*typedPortForwardParent, 0, len(s.parents))
	for _, parent := range s.parents {
		parents = append(parents, parent)
	}
	s.mu.Unlock()
	for _, parent := range parents {
		s.markParentClosed(parent)
	}

	results := make(chan error, len(parents))
	var wg sync.WaitGroup
	for _, parent := range parents {
		wg.Add(1)
		go func(parentID uint32) {
			defer wg.Done()
			results <- s.closeParent(parentID, "parent_session_closed", false)
		}(parent.id)
	}
	wg.Wait()
	close(results)
	var errs []error
	for err := range results {
		if err != nil {
			errs = append(errs, err)
		}
	}
	s.mu.Lock()
	errs = append(errs, s.closeErr)
	s.mu.Unlock()
	return errors.Join(errs...)
}

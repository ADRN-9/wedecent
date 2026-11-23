package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

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
	done        chan struct{}
	doneOnce    sync.Once
	closeOnce   sync.Once
}

type typedPortForwardServer struct {
	ctx       context.Context
	localID   mesh.DeviceID
	peerID    mesh.DeviceID
	routerID  mesh.DeviceID
	runtime   *PortForwardRuntime
	registry  *typedParentStreamRegistry
	write     typedTerminalFrameWriter

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
		ctx:       ctx,
		localID:   mesh.DeviceID(localID),
		peerID:    mesh.DeviceID(peerID),
		routerID:  mesh.DeviceID(routerID),
		runtime:   runtime,
		registry:  registry,
		write:     write,
		parents:   make(map[uint32]*typedPortForwardParent),
		children:  make(map[uint32]*typedPortForwardChild),
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
	if err := s.registry.accept(frame.StreamID, protocol.StreamKindPortForwardParent); err != nil {
		_ = s.closeParent(frame.StreamID, "registry_accept_failed", false)
		return err
	}
	if err := s.sendAccepted(frame.StreamID); err != nil {
		_ = s.closeParent(frame.StreamID, "transport_write_failed", false)
		return err
	}
	go s.watchDestinationParent(parent)
	return nil
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
		_ = s.sendStreamError(parent.id, "forwarding_session_ended", "forwarding authorization is no longer active")
		_ = s.closeParent(parent.id, "destination_session_ended", false)
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
	child := &typedPortForwardChild{
		id: frame.StreamID, parent: parent, conn: conn,
		sendCredit: sendCredit, recvCredit: recvCredit,
		creditCh: make(chan struct{}, 1), writeCh: make(chan struct{}, 1), done: make(chan struct{}),
	}
	s.mu.Lock()
	if s.closed || parent.closed || s.parents[parent.id] != parent {
		s.mu.Unlock()
		// The parent DestinationSession owns any child it registered before
		// shutdown. Do not issue a duplicate Close against its sync.Once.
		_ = s.registry.close(frame.StreamID, protocol.StreamKindPortForwardChild)
		return s.sendStreamError(frame.StreamID, "parent_stream_unavailable", "forwarding parent stream is unavailable")
	}
	s.children[frame.StreamID] = child
	parent.children[frame.StreamID] = child
	s.mu.Unlock()
	if err := s.registry.accept(frame.StreamID, protocol.StreamKindPortForwardChild); err != nil {
		_ = s.closeChild(frame.StreamID, "registry_accept_failed", false)
		return err
	}
	if err := s.sendAccepted(frame.StreamID); err != nil {
		_ = s.closeChild(frame.StreamID, "transport_write_failed", false)
		return err
	}
	go s.forwardInput(child)
	go s.forwardOutput(child)
	return nil
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
	select {
	case <-child.done:
		child.mu.Unlock()
		return fmt.Errorf("%w: forwarding child is closed", errTypedStreamProtocol)
	default:
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
		child.mu.Lock()
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
			n, err := child.conn.Write(remaining)
			if err != nil || n <= 0 {
				if err == nil {
					err = io.ErrShortWrite
				}
				_ = s.closeChild(child.id, "destination_write_failed", false)
				if s.ctx.Err() == nil {
					_ = s.sendStreamError(child.id, "destination_write_failed", "destination connection write failed")
				}
				return
			}
			remaining = remaining[n:]
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
		if err := s.write(protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: child.id, Payload: payload}); err != nil {
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
	writer, ok := child.conn.(interface{ CloseWrite() error })
	if !ok {
		_ = s.sendStreamError(frame.StreamID, "half_close_unsupported", "destination transport does not support TCP half-close")
		_ = s.closeChild(frame.StreamID, "half_close_unsupported", false)
		return nil
	}
	if err := writer.CloseWrite(); err != nil {
		_ = s.sendStreamError(frame.StreamID, "half_close_failed", "destination TCP half-close failed")
		_ = s.closeChild(frame.StreamID, "half_close_failed", false)
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
		n, readErr := child.conn.Read(buffer)
		if n > 0 {
			if err := s.sendData(child, buffer[:n]); err != nil {
				_ = s.closeChild(child.id, "transport_write_failed", false)
				return
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if err := s.write(protocol.Frame{Type: protocol.TypeStreamHalfClose, StreamID: child.id}); err != nil {
					_ = s.closeChild(child.id, "transport_write_failed", false)
				}
				return
			}
			if !errors.Is(readErr, net.ErrClosed) && !errors.Is(readErr, io.ErrClosedPipe) {
				_ = s.sendStreamError(child.id, "destination_read_failed", "destination connection read failed")
			}
			_ = s.closeChild(child.id, "destination_read_failed", false)
			return
		}
		if n == 0 {
			_ = s.closeChild(child.id, "destination_read_failed", false)
			return
		}
	}
}

func (s *typedPortForwardServer) sendData(child *typedPortForwardChild, data []byte) error {
	for offset := 0; offset < len(data); {
		var count int
		for count == 0 {
			child.mu.Lock()
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
		if err := s.write(protocol.Frame{Type: protocol.TypeStreamData, StreamID: child.id, Payload: append([]byte(nil), data[offset:offset+count]...)}); err != nil {
			return err
		}
		offset += count
	}
	return nil
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
	if child != nil {
		delete(s.children, streamID)
		delete(child.parent.children, streamID)
	}
	s.mu.Unlock()
	if child == nil {
		return nil
	}
	var closeErr error
	child.doneOnce.Do(func() { close(child.done) })
	child.closeOnce.Do(func() { closeErr = child.conn.Close() })
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
	if child != nil {
		delete(s.children, streamID)
		delete(child.parent.children, streamID)
	}
	s.mu.Unlock()
	if child == nil {
		return
	}
	// The parent DestinationSession has already attempted to close every
	// child. Do not call destinationChildConn.Close a second time: its
	// sync.Once may still be executing a blocked underlying Close.
	child.doneOnce.Do(func() { close(child.done) })
	_ = s.registry.close(streamID, protocol.StreamKindPortForwardChild)
}

func (s *typedPortForwardServer) closeParent(streamID uint32, reason string, acknowledge bool) error {
	s.mu.Lock()
	parent := s.parents[streamID]
	if parent != nil {
		parent.closed = true
	}
	s.mu.Unlock()
	if parent == nil {
		return nil
	}

	parent.closeOnce.Do(func() {
		var errs []error
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
	parents := make([]uint32, 0, len(s.parents))
	for id := range s.parents {
		parents = append(parents, id)
	}
	s.mu.Unlock()

	results := make(chan error, len(parents))
	var wg sync.WaitGroup
	for _, id := range parents {
		wg.Add(1)
		go func(parentID uint32) {
			defer wg.Done()
			results <- s.closeParent(parentID, "parent_session_closed", false)
		}(id)
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

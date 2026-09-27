package coreapi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const (
	terminalStreamIDPrefix   = "term_"
	terminalStreamCloseWait  = 2 * time.Second
	terminalStreamIDRawBytes = 18
)

// MultiplexTerminalConnectionHandle is an internal backend capability. Wire
// stream IDs never cross the Core boundary; Core maps them to opaque terminal
// IDs before returning anything to a caller.
type MultiplexTerminalConnectionHandle interface {
	TerminalConnectionHandle
	ObservableConnectionHandle
	OpenTerminalStream(context.Context, uint16, uint16, string) (uint32, error)
	ReadTerminalStream(context.Context, uint32, int) ([]byte, bool, error)
	WriteTerminalStream(context.Context, uint32, []byte) error
	ResizeTerminalStream(context.Context, uint32, uint16, uint16) error
	CloseTerminalStream(context.Context, uint32) error
}

type multiplexTerminalChildHandle struct {
	parent   MultiplexTerminalConnectionHandle
	streamID uint32
	stop     chan struct{}
	stopOnce sync.Once
}

func (h *multiplexTerminalChildHandle) ReadTerminal(ctx context.Context, maxBytes int) ([]byte, bool, error) {
	return h.parent.ReadTerminalStream(ctx, h.streamID, maxBytes)
}

func (h *multiplexTerminalChildHandle) WriteTerminal(ctx context.Context, data []byte) error {
	return h.parent.WriteTerminalStream(ctx, h.streamID, data)
}

func (h *multiplexTerminalChildHandle) ResizeTerminal(ctx context.Context, cols, rows uint16) error {
	return h.parent.ResizeTerminalStream(ctx, h.streamID, cols, rows)
}

func (h *multiplexTerminalChildHandle) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), terminalStreamCloseWait)
	defer cancel()
	return h.closeContext(ctx)
}

func (h *multiplexTerminalChildHandle) closeContext(ctx context.Context) error {
	return h.parent.CloseTerminalStream(ctx, h.streamID)
}

func (h *multiplexTerminalChildHandle) stopWatch() {
	h.stopOnce.Do(func() { close(h.stop) })
}

var _ v1.TerminalStreamService = (*ConnectionService)(nil)
var _ TerminalConnectionHandle = (*multiplexTerminalChildHandle)(nil)

func (s *ConnectionService) OpenTerminalStream(ctx context.Context, req v1.TerminalStreamOpenRequest) (v1.TerminalStream, error) {
	if err := ctx.Err(); err != nil {
		return v1.TerminalStream{}, err
	}
	if !validConnectionID(req.ConnectionID) || req.Cols == 0 || req.Rows == 0 || !validTerminalType(req.Term) {
		return v1.TerminalStream{}, ErrInvalidTerminalRequest
	}

	parent, token, done, err := s.activeMultiplexTerminal(req.ConnectionID)
	if err != nil {
		return v1.TerminalStream{}, err
	}
	terminalID, err := s.reserveTerminalStreamID()
	if err != nil {
		if errors.Is(err, ErrConnectionServiceClosed) {
			return v1.TerminalStream{}, err
		}
		return v1.TerminalStream{}, fmt.Errorf("%w: generate terminal stream ID", ErrTerminalOperation)
	}
	reserved := true
	defer func() {
		if reserved {
			s.releaseTerminalStreamID(terminalID)
		}
	}()

	backendID, err := parent.OpenTerminalStream(ctx, req.Cols, req.Rows, req.Term)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return v1.TerminalStream{}, ctxErr
		}
		return v1.TerminalStream{}, ErrTerminalUnavailable
	}
	child := &multiplexTerminalChildHandle{
		parent:   parent,
		streamID: backendID,
		stop:     make(chan struct{}),
	}
	cleanupBackend := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), terminalStreamCloseWait)
		defer cancel()
		_ = child.closeContext(cleanupCtx)
	}

	if err := ctx.Err(); err != nil {
		cleanupBackend()
		return v1.TerminalStream{}, err
	}

	s.mu.Lock()
	if s.closed {
		delete(s.reserved, terminalID)
		s.mu.Unlock()
		reserved = false
		cleanupBackend()
		return v1.TerminalStream{}, ErrConnectionServiceClosed
	}
	active, ok := s.active[req.ConnectionID]
	if !ok || active.closing || active.token != token {
		delete(s.reserved, terminalID)
		s.mu.Unlock()
		reserved = false
		cleanupBackend()
		return v1.TerminalStream{}, ErrConnectionNotFound
	}
	if _, exists := s.streams[terminalID]; exists {
		delete(s.reserved, terminalID)
		s.mu.Unlock()
		reserved = false
		cleanupBackend()
		return v1.TerminalStream{}, fmt.Errorf("%w: terminal stream ID collision", ErrTerminalOperation)
	}
	s.streams[terminalID] = terminalStreamEntry{handle: child, token: token}
	delete(s.reserved, terminalID)
	reserved = false
	s.mu.Unlock()

	go s.watchLogicalTerminalParent(terminalID, token, child, done)
	return v1.TerminalStream{ID: terminalID, ConnectionID: req.ConnectionID}, nil
}

func (s *ConnectionService) CloseTerminalStream(ctx context.Context, req v1.TerminalStreamCloseRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	child, token, err := s.logicalTerminalStream(req.ConnectionID, req.TerminalID)
	if err != nil {
		return err
	}
	if err := child.closeContext(ctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: close terminal stream", ErrTerminalOperation)
	}
	s.removeLogicalTerminal(req.TerminalID, token, child)
	child.stopWatch()
	return nil
}

func (s *ConnectionService) ReadTerminalStream(ctx context.Context, req v1.TerminalStreamReadRequest) (v1.TerminalReadResult, error) {
	if err := ctx.Err(); err != nil {
		return v1.TerminalReadResult{}, err
	}
	maxBytes := req.MaxBytes
	if maxBytes == 0 {
		maxBytes = v1.MaxTerminalChunkBytes
	}
	if maxBytes < 1 || maxBytes > v1.MaxTerminalChunkBytes {
		return v1.TerminalReadResult{}, ErrInvalidTerminalRequest
	}
	child, token, err := s.logicalTerminalStream(req.ConnectionID, req.TerminalID)
	if err != nil {
		return v1.TerminalReadResult{}, err
	}

	readCtx, cancelRead := context.WithTimeout(ctx, terminalReadWait)
	defer cancelRead()
	data, closed, err := child.ReadTerminal(readCtx, maxBytes)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return v1.TerminalReadResult{}, ctxErr
		}
		if readCtx.Err() != nil {
			return v1.TerminalReadResult{}, nil
		}
		return v1.TerminalReadResult{}, fmt.Errorf("%w: read terminal stream", ErrTerminalOperation)
	}
	result := v1.TerminalReadResult{Data: append([]byte(nil), data...), Closed: closed}
	if closed {
		s.removeLogicalTerminal(req.TerminalID, token, child)
		child.stopWatch()
	}
	return result, nil
}

func (s *ConnectionService) WriteTerminalStream(ctx context.Context, req v1.TerminalStreamWriteRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(req.Data) < 1 || len(req.Data) > v1.MaxTerminalChunkBytes {
		return ErrInvalidTerminalRequest
	}
	child, _, err := s.logicalTerminalStream(req.ConnectionID, req.TerminalID)
	if err != nil {
		return err
	}
	if err := child.WriteTerminal(ctx, append([]byte(nil), req.Data...)); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: write terminal stream", ErrTerminalOperation)
	}
	return nil
}

func (s *ConnectionService) ResizeTerminalStream(ctx context.Context, req v1.TerminalStreamResizeRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Cols == 0 || req.Rows == 0 {
		return ErrInvalidTerminalRequest
	}
	child, _, err := s.logicalTerminalStream(req.ConnectionID, req.TerminalID)
	if err != nil {
		return err
	}
	if err := child.ResizeTerminal(ctx, req.Cols, req.Rows); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: resize terminal stream", ErrTerminalOperation)
	}
	return nil
}

func (s *ConnectionService) activeMultiplexTerminal(connectionID string) (MultiplexTerminalConnectionHandle, *connectionGeneration, <-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, nil, ErrConnectionServiceClosed
	}
	active, ok := s.active[connectionID]
	if !ok || active.closing {
		return nil, nil, nil, ErrConnectionNotFound
	}
	parent, ok := active.handle.(MultiplexTerminalConnectionHandle)
	if !ok {
		return nil, nil, nil, ErrTerminalUnavailable
	}
	done := parent.Done()
	if done == nil {
		return nil, nil, nil, ErrTerminalUnavailable
	}
	return parent, active.token, done, nil
}

func (s *ConnectionService) logicalTerminalStream(connectionID, terminalID string) (*multiplexTerminalChildHandle, *connectionGeneration, error) {
	if !validConnectionID(connectionID) || !validTerminalStreamID(terminalID) {
		return nil, nil, ErrInvalidTerminalRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, ErrConnectionServiceClosed
	}
	active, ok := s.active[connectionID]
	if !ok || active.closing {
		return nil, nil, ErrConnectionNotFound
	}
	entry, ok := s.streams[terminalID]
	if !ok || entry.token != active.token {
		return nil, nil, ErrTerminalUnavailable
	}
	child, ok := entry.handle.(*multiplexTerminalChildHandle)
	if !ok {
		return nil, nil, ErrTerminalUnavailable
	}
	return child, entry.token, nil
}

func (s *ConnectionService) watchLogicalTerminalParent(terminalID string, token *connectionGeneration, child *multiplexTerminalChildHandle, done <-chan struct{}) {
	select {
	case <-done:
		s.removeLogicalTerminal(terminalID, token, child)
		child.stopWatch()
	case <-child.stop:
	}
}

func (s *ConnectionService) removeLogicalTerminal(terminalID string, token *connectionGeneration, child *multiplexTerminalChildHandle) {
	s.mu.Lock()
	if current, ok := s.streams[terminalID]; ok && current.token == token && current.handle == child {
		delete(s.streams, terminalID)
	}
	s.mu.Unlock()
}

func (s *ConnectionService) reserveTerminalStreamID() (string, error) {
	for attempt := 0; attempt < maxConnectionIDAttempts; attempt++ {
		terminalID, err := s.newTerminalStreamID()
		if err != nil {
			return "", err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return "", ErrConnectionServiceClosed
		}
		_, active := s.active[terminalID]
		_, stream := s.streams[terminalID]
		_, reserved := s.reserved[terminalID]
		if !active && !stream && !reserved {
			s.reserved[terminalID] = struct{}{}
			s.mu.Unlock()
			return terminalID, nil
		}
		s.mu.Unlock()
	}
	return "", errors.New("terminal stream ID collision limit reached")
}

func (s *ConnectionService) releaseTerminalStreamID(terminalID string) {
	s.mu.Lock()
	delete(s.reserved, terminalID)
	s.mu.Unlock()
}

func (s *ConnectionService) newTerminalStreamID() (string, error) {
	var raw [terminalStreamIDRawBytes]byte
	if _, err := io.ReadFull(s.random, raw[:]); err != nil {
		return "", err
	}
	return terminalStreamIDPrefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func validTerminalStreamID(value string) bool {
	if !strings.HasPrefix(value, terminalStreamIDPrefix) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, terminalStreamIDPrefix))
	return err == nil && len(raw) == terminalStreamIDRawBytes
}

func validTerminalType(term string) bool {
	if len(term) > v1.MaxTerminalTypeBytes {
		return false
	}
	for i := 0; i < len(term); i++ {
		b := term[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '+' {
			continue
		}
		return false
	}
	return true
}

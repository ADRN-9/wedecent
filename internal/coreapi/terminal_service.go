package coreapi

import (
	"context"
	"fmt"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

// terminalReadWait keeps terminal.read comfortably below localserver's bounded
// request lifetime. An idle read returns an empty, still-open result instead of
// occupying one IPC request until the outer server deadline expires.
const terminalReadWait = time.Second

func (s *ConnectionService) ReadTerminal(ctx context.Context, req v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	if err := ctx.Err(); err != nil {
		return v1.TerminalReadResult{}, err
	}
	if !validConnectionID(req.ConnectionID) {
		return v1.TerminalReadResult{}, ErrInvalidTerminalRequest
	}
	maxBytes := req.MaxBytes
	if maxBytes == 0 {
		maxBytes = v1.MaxTerminalChunkBytes
	}
	if maxBytes < 1 || maxBytes > v1.MaxTerminalChunkBytes {
		return v1.TerminalReadResult{}, ErrInvalidTerminalRequest
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return v1.TerminalReadResult{}, ErrConnectionServiceClosed
	}
	stream, ok := s.streams[req.ConnectionID]
	_, active := s.active[req.ConnectionID]
	s.mu.Unlock()
	if !ok {
		if active {
			return v1.TerminalReadResult{}, ErrTerminalUnavailable
		}
		return v1.TerminalReadResult{}, ErrConnectionNotFound
	}

	readCtx, cancelRead := context.WithTimeout(ctx, terminalReadWait)
	defer cancelRead()
	data, closed, err := stream.handle.ReadTerminal(readCtx, maxBytes)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return v1.TerminalReadResult{}, ctxErr
		}
		if readCtx.Err() != nil {
			return v1.TerminalReadResult{}, nil
		}
		return v1.TerminalReadResult{}, fmt.Errorf("%w: read terminal", ErrTerminalOperation)
	}
	result := v1.TerminalReadResult{
		Data:   append([]byte(nil), data...),
		Closed: closed,
	}
	if closed {
		s.mu.Lock()
		if current, exists := s.streams[req.ConnectionID]; exists && current.token == stream.token {
			delete(s.streams, req.ConnectionID)
		}
		s.mu.Unlock()
	}
	return result, nil
}

func (s *ConnectionService) WriteTerminal(ctx context.Context, req v1.TerminalWriteRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validConnectionID(req.ConnectionID) || len(req.Data) < 1 || len(req.Data) > v1.MaxTerminalChunkBytes {
		return ErrInvalidTerminalRequest
	}
	stream, err := s.activeTerminalStream(req.ConnectionID)
	if err != nil {
		return err
	}
	if err := stream.handle.WriteTerminal(ctx, append([]byte(nil), req.Data...)); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: write terminal", ErrTerminalOperation)
	}
	return nil
}

func (s *ConnectionService) ResizeTerminal(ctx context.Context, req v1.TerminalResizeRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validConnectionID(req.ConnectionID) || req.Cols == 0 || req.Rows == 0 {
		return ErrInvalidTerminalRequest
	}
	stream, err := s.activeTerminalStream(req.ConnectionID)
	if err != nil {
		return err
	}
	if err := stream.handle.ResizeTerminal(ctx, req.Cols, req.Rows); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: resize terminal", ErrTerminalOperation)
	}
	return nil
}

func (s *ConnectionService) activeTerminalStream(connectionID string) (terminalStreamEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return terminalStreamEntry{}, ErrConnectionServiceClosed
	}
	active, ok := s.active[connectionID]
	if !ok || active.closing {
		return terminalStreamEntry{}, ErrConnectionNotFound
	}
	stream, ok := s.streams[connectionID]
	if !ok || stream.token != active.token || stream.closed {
		return terminalStreamEntry{}, ErrTerminalUnavailable
	}
	return stream, nil
}

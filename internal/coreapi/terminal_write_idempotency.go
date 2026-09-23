package coreapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const defaultMaxTerminalWriteOperations = 16384

type terminalWriteOperation struct {
	connectionID string
	dataDigest   [sha256.Size]byte
	done         chan struct{}
	completed    bool
	completedAt  time.Time
	err          error
}

// TerminalWriteIdempotencyService adds bounded, process-local replay protection
// to terminal.write without retaining terminal plaintext. The wrapped terminal
// service remains authoritative for stream/session state.
type TerminalWriteIdempotencyService struct {
	inner v1.TerminalService

	mu         sync.Mutex
	operations map[string]*terminalWriteOperation
	retention  time.Duration
	maxEntries int
	now        func() time.Time
}

var _ v1.TerminalService = (*TerminalWriteIdempotencyService)(nil)

func NewTerminalWriteIdempotencyService(inner v1.TerminalService) (*TerminalWriteIdempotencyService, error) {
	if inner == nil {
		return nil, errors.New("terminal service is required")
	}
	return &TerminalWriteIdempotencyService{
		inner:      inner,
		operations: make(map[string]*terminalWriteOperation),
		retention:  v1.TerminalWriteReplayWindow,
		maxEntries: defaultMaxTerminalWriteOperations,
		now:        time.Now,
	}, nil
}

func (s *TerminalWriteIdempotencyService) ReadTerminal(ctx context.Context, req v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	return s.inner.ReadTerminal(ctx, req)
}

func (s *TerminalWriteIdempotencyService) ResizeTerminal(ctx context.Context, req v1.TerminalResizeRequest) error {
	return s.inner.ResizeTerminal(ctx, req)
}

func (s *TerminalWriteIdempotencyService) WriteTerminal(ctx context.Context, req v1.TerminalWriteRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.OperationID == "" {
		return s.inner.WriteTerminal(ctx, req)
	}
	if !validConnectionID(req.ConnectionID) || len(req.Data) < 1 || len(req.Data) > v1.MaxTerminalChunkBytes || !validTerminalWriteOperationID(req.OperationID) {
		return ErrInvalidTerminalRequest
	}

	payload := append([]byte(nil), req.Data...)
	defer wipeTerminalWritePayload(payload)
	req.Data = payload
	digest := sha256.Sum256(payload)

	for {
		op, leader, err := s.beginTerminalWrite(req, digest)
		if err != nil {
			return err
		}
		if leader {
			writeErr := s.inner.WriteTerminal(ctx, req)
			s.completeTerminalWrite(req.OperationID, op, writeErr)
			return writeErr
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-op.done:
		}

		s.mu.Lock()
		current, ok := s.operations[req.OperationID]
		if ok && current == op && current.completed {
			writeErr := current.err
			s.mu.Unlock()
			return writeErr
		}
		s.mu.Unlock()
	}
}

func (s *TerminalWriteIdempotencyService) beginTerminalWrite(req v1.TerminalWriteRequest, digest [sha256.Size]byte) (*terminalWriteOperation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneTerminalWritesLocked(s.now())
	if existing, ok := s.operations[req.OperationID]; ok {
		if existing.connectionID != req.ConnectionID || existing.dataDigest != digest {
			return nil, false, ErrInvalidTerminalRequest
		}
		return existing, false, nil
	}
	if len(s.operations) >= s.maxEntries {
		return nil, false, ErrTerminalUnavailable
	}
	op := &terminalWriteOperation{
		connectionID: req.ConnectionID,
		dataDigest:   digest,
		done:         make(chan struct{}),
	}
	s.operations[req.OperationID] = op
	return op, true, nil
}

func (s *TerminalWriteIdempotencyService) completeTerminalWrite(operationID string, op *terminalWriteOperation, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.operations[operationID]
	if !ok || current != op {
		return
	}
	// Cache every completed outcome, including cancellation/deadline errors.
	// Once the terminal handle was invoked, cancellation is not proof that the
	// bytes were not delivered, so dropping the replay key could duplicate input.
	op.err = err
	op.completed = true
	op.completedAt = s.now()
	close(op.done)
}

func (s *TerminalWriteIdempotencyService) pruneTerminalWritesLocked(now time.Time) {
	for operationID, op := range s.operations {
		if !op.completed {
			continue
		}
		if now.Sub(op.completedAt) >= s.retention {
			delete(s.operations, operationID)
		}
	}
}

func validTerminalWriteOperationID(value string) bool {
	if value == "" || len(value) > v1.MaxTerminalWriteOperationIDBytes {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func wipeTerminalWritePayload(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

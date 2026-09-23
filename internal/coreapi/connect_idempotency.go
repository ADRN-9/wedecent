package coreapi

import (
	"context"
	"errors"
	"sync"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const defaultMaxConnectOperations = 4096

type connectOperation struct {
	deviceID    string
	done        chan struct{}
	completed   bool
	completedAt time.Time
	result      v1.Connection
	err         error
}

// ConnectIdempotencyService adds bounded, process-local replay protection to
// connection.connect without duplicating connection ownership. The wrapped
// service remains authoritative for handles, routes, limits, terminal streams,
// and shutdown.
type ConnectIdempotencyService struct {
	inner v1.ConnectionService

	mu         sync.Mutex
	operations map[string]*connectOperation
	retention  time.Duration
	maxEntries int
	now        func() time.Time
}

var _ v1.ConnectionService = (*ConnectIdempotencyService)(nil)

func NewConnectIdempotencyService(inner v1.ConnectionService) (*ConnectIdempotencyService, error) {
	if inner == nil {
		return nil, errors.New("connection service is required")
	}
	return &ConnectIdempotencyService{
		inner:      inner,
		operations: make(map[string]*connectOperation),
		retention:  v1.ConnectOperationReplayWindow,
		maxEntries: defaultMaxConnectOperations,
		now:        time.Now,
	}, nil
}

func (s *ConnectIdempotencyService) Connect(ctx context.Context, req v1.ConnectRequest) (v1.Connection, error) {
	if err := ctx.Err(); err != nil {
		return v1.Connection{}, err
	}
	if req.OperationID == "" {
		return s.inner.Connect(ctx, req)
	}
	if !validConnectOperationID(req.OperationID) {
		return v1.Connection{}, ErrInvalidConnectionRequest
	}

	for {
		op, leader, err := s.begin(req)
		if err != nil {
			return v1.Connection{}, err
		}
		if leader {
			result, connectErr := s.inner.Connect(ctx, req)
			s.complete(req.OperationID, op, result, connectErr)
			return result, connectErr
		}

		select {
		case <-ctx.Done():
			return v1.Connection{}, ctx.Err()
		case <-op.done:
		}

		s.mu.Lock()
		current, ok := s.operations[req.OperationID]
		if ok && current == op && current.completed {
			result, operationErr := current.result, current.err
			s.mu.Unlock()
			return result, operationErr
		}
		s.mu.Unlock()
		// A canceled/deadline-exceeded leader is deliberately not cached. A
		// still-live duplicate caller may become the next leader.
	}
}

func (s *ConnectIdempotencyService) Disconnect(ctx context.Context, req v1.DisconnectRequest) error {
	return s.inner.Disconnect(ctx, req)
}

func (s *ConnectIdempotencyService) begin(req v1.ConnectRequest) (*connectOperation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneLocked(s.now())
	if existing, ok := s.operations[req.OperationID]; ok {
		if existing.deviceID != req.DeviceID {
			return nil, false, ErrInvalidConnectionRequest
		}
		return existing, false, nil
	}
	if len(s.operations) >= s.maxEntries {
		// Never evict a live/unexpired replay key just to admit another key;
		// failing closed preserves idempotency and bounds memory.
		return nil, false, ErrConnectionLimit
	}
	op := &connectOperation{deviceID: req.DeviceID, done: make(chan struct{})}
	s.operations[req.OperationID] = op
	return op, true, nil
}

func (s *ConnectIdempotencyService) complete(operationID string, op *connectOperation, result v1.Connection, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.operations[operationID]
	if !ok || current != op {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		delete(s.operations, operationID)
		close(op.done)
		return
	}
	op.result = result
	op.err = err
	op.completed = true
	op.completedAt = s.now()
	close(op.done)
}

func (s *ConnectIdempotencyService) pruneLocked(now time.Time) {
	for operationID, op := range s.operations {
		if !op.completed {
			continue
		}
		if now.Sub(op.completedAt) >= s.retention {
			delete(s.operations, operationID)
		}
	}
}

func validConnectOperationID(value string) bool {
	if value == "" || len(value) > v1.MaxConnectOperationIDBytes {
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

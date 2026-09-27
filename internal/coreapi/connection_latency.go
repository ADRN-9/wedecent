package coreapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

var (
	ErrConnectionLatencyUnavailable = errors.New("connection latency is unavailable")
	ErrConnectionLatencyOperation   = errors.New("connection latency probe failed")
)

// LatencyConnectionHandle is an optional capability of an already-authenticated
// connection handle. Implementations must probe only the existing secure
// application session and must not dial, discover, select a route, or establish
// trust as part of the measurement.
type LatencyConnectionHandle interface {
	ConnectionHandle
	ProbeLatency(context.Context) (time.Duration, error)
}

var _ v1.ConnectionMetricsService = (*ConnectionService)(nil)

func (s *ConnectionService) ProbeConnectionLatency(ctx context.Context, req v1.ConnectionLatencyRequest) (v1.ConnectionLatency, error) {
	if err := ctx.Err(); err != nil {
		return v1.ConnectionLatency{}, err
	}
	if !validConnectionID(req.ConnectionID) {
		return v1.ConnectionLatency{}, ErrInvalidConnectionRequest
	}

	s.mu.Lock()
	active, ok := s.active[req.ConnectionID]
	if !ok || active.closing {
		s.mu.Unlock()
		return v1.ConnectionLatency{}, ErrConnectionNotFound
	}
	probe, ok := active.handle.(LatencyConnectionHandle)
	s.mu.Unlock()
	if !ok {
		return v1.ConnectionLatency{}, ErrConnectionLatencyUnavailable
	}

	rtt, err := probe.ProbeLatency(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return v1.ConnectionLatency{}, ctxErr
		}
		return v1.ConnectionLatency{}, fmt.Errorf("%w", ErrConnectionLatencyOperation)
	}
	micros := rtt.Microseconds()
	if micros < 1 {
		micros = 1
	}
	return v1.ConnectionLatency{
		ConnectionID: req.ConnectionID,
		RTTMicros:    uint64(micros),
		MeasuredAt:   s.now().UTC(),
	}, nil
}

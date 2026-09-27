package coreapi

import (
	"context"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

var _ v1.ConnectionMetricsService = (*ConnectIdempotencyService)(nil)

func (s *ConnectIdempotencyService) ProbeConnectionLatency(ctx context.Context, req v1.ConnectionLatencyRequest) (v1.ConnectionLatency, error) {
	metrics, ok := s.inner.(v1.ConnectionMetricsService)
	if !ok {
		return v1.ConnectionLatency{}, ErrConnectionLatencyUnavailable
	}
	return metrics.ProbeConnectionLatency(ctx, req)
}

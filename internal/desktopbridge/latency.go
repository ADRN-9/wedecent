package desktopbridge

import (
	"context"
	"fmt"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type LatencySource interface {
	ProbeConnectionLatency(context.Context, v1.ConnectionLatencyRequest) (v1.ConnectionLatency, error)
}

type ConnectionLatencySummary struct {
	RTTMicros uint64 `json:"rtt_micros"`
}

func ProbeConnectionLatency(ctx context.Context, source LatencySource, connectionID string) (ConnectionLatencySummary, error) {
	if err := validatePublicID(connectionID); err != nil {
		return ConnectionLatencySummary{}, err
	}
	latency, err := source.ProbeConnectionLatency(ctx, v1.ConnectionLatencyRequest{ConnectionID: connectionID})
	if err != nil {
		return ConnectionLatencySummary{}, err
	}
	if latency.ConnectionID != connectionID || latency.RTTMicros == 0 {
		return ConnectionLatencySummary{}, fmt.Errorf("%w: invalid latency result from Local Core", ErrInvalidTerminalBridgeRequest)
	}
	return ConnectionLatencySummary{RTTMicros: latency.RTTMicros}, nil
}

package client

import (
	"context"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func (c *Client) ProbeConnectionLatency(ctx context.Context, req v1.ConnectionLatencyRequest) (v1.ConnectionLatency, error) {
	var out v1.ConnectionLatency
	err := c.call(ctx, v1.MethodConnectionLatency, req, &out)
	return out, err
}

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"wedecent.com/wedecent/internal/transport"
)

const serialSessionReopenDelay = 250 * time.Millisecond

var dialAgentSerial = func(ctx context.Context, endpoint string) (net.Conn, error) {
	conn, err := (transport.SerialDialer{}).Dial(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// serveAgentSerial repeatedly opens one explicitly configured serial stream and
// hands it to the normal direct-session handler. CDC-ACM is a single stream,
// not a listener, so sessions are intentionally serialized. Any device-open
// failure is fatal instead of silently leaving the agent partially available.
func serveAgentSerial(
	ctx context.Context,
	endpoint string,
	handle func(net.Conn),
) error {
	if ctx == nil {
		return errors.New("wd-agent: nil serial serve context")
	}
	if endpoint == "" {
		return errors.New("wd-agent: serial endpoint is required")
	}
	if handle == nil {
		return errors.New("wd-agent: serial session handler is unavailable")
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		conn, err := dialAgentSerial(ctx, endpoint)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("wd-agent: open serial endpoint %s: %w", endpoint, err)
		}

		stopClose := context.AfterFunc(ctx, func() {
			_ = conn.Close()
		})
		handle(conn)
		stopClose()
		_ = conn.Close()

		if ctx.Err() != nil {
			return nil
		}

		timer := time.NewTimer(serialSessionReopenDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

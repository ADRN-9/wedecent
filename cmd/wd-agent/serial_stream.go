package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/session"
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

func validateAgentSerialEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	if strings.TrimSpace(endpoint) != endpoint {
		return errors.New("serial device path must not contain surrounding whitespace")
	}
	if strings.IndexByte(endpoint, 0) >= 0 || strings.ContainsAny(endpoint, "?#") {
		return errors.New("invalid serial device path")
	}
	if endpoint == "/dev" || !strings.HasPrefix(endpoint, "/dev/") || path.Clean(endpoint) != endpoint {
		return errors.New("serial device path must be a canonical absolute path under /dev")
	}
	return nil
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

func serveAgentLocalTransports(
	ctx context.Context,
	listeners *agentListenerSet,
	serialEndpoint string,
	server *session.Server,
) error {
	if listeners == nil {
		return errors.New("wd-agent: local listener set is unavailable")
	}
	if serialEndpoint == "" {
		return listeners.serve(ctx)
	}
	if server == nil {
		return errors.New("wd-agent: endpoint session server is unavailable")
	}

	localCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		errCh <- listeners.serve(localCtx)
	}()
	go func() {
		errCh <- serveAgentSerial(localCtx, serialEndpoint, server.ServeConn)
	}()

	firstErr := <-errCh
	cancel()
	listeners.close()
	secondErr := <-errCh

	if ctx.Err() != nil {
		return nil
	}
	if firstErr != nil {
		return firstErr
	}
	if secondErr != nil {
		return secondErr
	}
	return errors.New("wd-agent: local transport stopped unexpectedly")
}

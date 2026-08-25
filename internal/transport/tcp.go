package transport

import (
	"context"
	"net"
	"time"
)

type TCPDialer struct {
	Timeout time.Duration
}

func (d TCPDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	nd := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	conn, err := nd.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	return conn, nil
}

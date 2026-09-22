package session

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

// Connection is an authenticated, authorized non-terminal application session.
// It owns the underlying TLS connection and reports natural remote closure through
// Done. The request context used to open the connection does not own its lifetime.
type Connection struct {
	conn *tls.Conn

	writeMu   sync.Mutex
	closeOnce sync.Once
	doneOnce  sync.Once
	done      chan struct{}
}

// OpenConnection establishes a trusted WeDecent TLS connection and completes
// the application-level connection authorization handshake. Direct, legacy
// relay, and routed transports carry the connection grant in-band. Web relay
// connections are already authorized by the outer relay and therefore use the
// grant-free inner open message, matching ConnectTerminal semantics.
func (c *Client) OpenConnection(ctx context.Context, peer trust.Peer) (*Connection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inBandAuthorization, grant, err := connectionAuthorization(peer, c.ConnectionGrant)
	if err != nil {
		return nil, err
	}

	raw, err := c.dial(ctx, peer.Endpoint)
	if err != nil {
		return nil, err
	}
	conn, err := tlsClientContext(ctx, raw, c.Identity, peer.Fingerprint)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	deadline := time.Now().Add(15 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	frame := protocol.Frame{Type: protocol.TypeOpenConnection}
	if inBandAuthorization {
		payload, marshalErr := protocol.JSON(protocol.OpenAuthorizedConnection{ConnectionGrant: grant})
		if marshalErr != nil {
			_ = conn.Close()
			return nil, marshalErr
		}
		frame.Type = protocol.TypeOpenAuthorizedConnection
		frame.Payload = payload
	}
	if err := protocol.WriteFrame(conn, frame); err != nil {
		_ = conn.Close()
		return nil, err
	}
	first, err := protocol.ReadFrame(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if first.Type == protocol.TypeError {
		_ = conn.Close()
		return nil, protocolError(first.Payload)
	}
	if first.Type != protocol.TypeConnectionAccepted {
		_ = conn.Close()
		return nil, errors.New("connection was not accepted")
	}
	_ = conn.SetDeadline(time.Time{})

	session := &Connection{conn: conn, done: make(chan struct{})}
	go session.readLoop()
	return session, nil
}

func (c *Connection) Done() <-chan struct{} {
	if c == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return c.done
}

// Close is idempotent. It closes at the application boundary first, allowing
// the peer to acknowledge and end the TLS stream cleanly. If the peer does not
// finish promptly, the local TLS connection is force-closed. A peer that has
// already gone away is treated as already closed.
func (c *Connection) Close() error {
	if c == nil {
		return nil
	}
	select {
	case <-c.done:
		return nil
	default:
	}

	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		writeErr := protocol.WriteFrame(c.conn, protocol.Frame{Type: protocol.TypeClose})
		c.writeMu.Unlock()
		if writeErr != nil {
			c.finish()
			return
		}

		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-c.done:
			return
		case <-timer.C:
			c.finish()
		}
	})
	return nil
}

func (c *Connection) readLoop() {
	for {
		frame, err := protocol.ReadFrame(c.conn)
		if err != nil {
			c.finish()
			return
		}
		switch frame.Type {
		case protocol.TypePing:
			c.writeMu.Lock()
			err := protocol.WriteFrame(c.conn, protocol.Frame{Type: protocol.TypePong})
			c.writeMu.Unlock()
			if err != nil {
				c.finish()
				return
			}
		case protocol.TypePong:
			continue
		case protocol.TypeClose:
			c.writeMu.Lock()
			_ = protocol.WriteFrame(c.conn, protocol.Frame{Type: protocol.TypeClose})
			c.writeMu.Unlock()
			c.finish()
			return
		case protocol.TypeError:
			c.finish()
			return
		default:
			c.finish()
			return
		}
	}
}

func (c *Connection) finish() {
	_ = c.conn.Close()
	c.doneOnce.Do(func() { close(c.done) })
}

func connectionAuthorization(peer trust.Peer, connectionGrant string) (bool, string, error) {
	inBand := !strings.HasPrefix(strings.ToLower(strings.TrimSpace(peer.Endpoint)), "wsrelay://")
	if !inBand {
		return false, "", nil
	}
	grant := strings.TrimSpace(connectionGrant)
	if grant == "" || len(grant) > 16*1024 || strings.ContainsAny(grant, "\r\n\t ") {
		return false, "", errors.New("a valid connection grant is required for this transport")
	}
	return true, grant, nil
}

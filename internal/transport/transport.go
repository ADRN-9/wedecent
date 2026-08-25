package transport

import (
	"context"
	"net"
)

// Conn is deliberately net.Conn-compatible so TLS can wrap every transport.
// USB serial/Bluetooth adapters can provide synthetic Addr values and deadline handling.
type Conn interface {
	net.Conn
}

// Dialer opens an outbound stream. Bluetooth/USB/relay transports implement this.
type Dialer interface {
	Dial(context.Context, string) (Conn, error)
}

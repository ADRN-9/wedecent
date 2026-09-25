package transport

import (
	"context"
	"errors"
	"net"
)

const defaultSerialBaud = 115200

var errSerialUnsupported = errors.New("transport: serial is unsupported on this platform")

// SerialDialer opens an explicitly configured local serial character device.
// It performs no device discovery and carries no trust semantics; TLS and
// WeDecent identity verification remain above this transport boundary.
type SerialDialer struct {
	Baud int
}

func (d SerialDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	if ctx == nil {
		return nil, errors.New("transport: nil serial dial context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	baud := d.Baud
	if baud == 0 {
		baud = defaultSerialBaud
	}
	if baud != defaultSerialBaud {
		return nil, errors.New("transport: serial currently requires 115200 baud")
	}
	return dialSerial(ctx, endpoint, baud)
}

type serialAddr string

func (a serialAddr) Network() string { return "serial" }
func (a serialAddr) String() string  { return string(a) }

var _ net.Addr = serialAddr("")
var _ Dialer = SerialDialer{}

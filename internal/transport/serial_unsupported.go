//go:build !linux

package transport

import "context"

func dialSerial(context.Context, string, int) (Conn, error) {
	return nil, errSerialUnsupported
}

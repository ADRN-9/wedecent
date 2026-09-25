//go:build !linux

package transport

import "context"

func dialRFCOMM(context.Context, rfcommLocator) (Conn, error) {
	return nil, errRFCOMMUnsupported
}

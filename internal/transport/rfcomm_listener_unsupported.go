//go:build !linux && !windows

package transport

import "net"

func listenRFCOMM(uint8) (net.Listener, error) {
	return nil, errRFCOMMUnsupported
}

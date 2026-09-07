//go:build windows

package discovery

import (
	"net"
	"syscall"
)

func setIPv4MulticastInterface(conn *net.UDPConn, ip net.IP) error {
	v4 := ip.To4()
	if v4 == nil {
		return &net.AddrError{Err: "not an IPv4 address", Addr: ip.String()}
	}
	var addr [4]byte
	copy(addr[:], v4)

	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInet4Addr(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, addr)
	}); err != nil {
		return err
	}
	return sockErr
}

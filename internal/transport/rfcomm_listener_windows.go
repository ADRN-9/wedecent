//go:build windows

package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	procBind   = winsockDLL.NewProc("bind")
	procListen = winsockDLL.NewProc("listen")
	procAccept = winsockDLL.NewProc("accept")
)

func listenRFCOMM(channel uint8) (net.Listener, error) {
	if err := ensureWinsock(); err != nil {
		return nil, fmt.Errorf("transport: initialize Winsock for RFCOMM listener: %w", err)
	}

	socket, _, _ := procWSASocket.Call(
		windowsAFBTH,
		windowsSockStream,
		windowsBTHProtoRFCOMM,
	)
	if socket == ^uintptr(0) {
		return nil, fmt.Errorf("transport: create Windows RFCOMM listener socket: %w", lastWSAError())
	}
	owned := true
	defer func() {
		if owned {
			closeWindowsSocket(socket)
		}
	}()

	var nonblocking uint32 = 1
	r1, _, _ := procIOCTLSocket.Call(
		socket,
		windowsFIONBIO,
		uintptr(unsafe.Pointer(&nonblocking)),
	)
	if int32(r1) == -1 {
		return nil, fmt.Errorf("transport: configure Windows RFCOMM listener socket: %w", lastWSAError())
	}

	sa := windowsRFCOMMSockaddr(rfcommLocator{channel: channel})
	r1, _, _ = procBind.Call(
		socket,
		uintptr(unsafe.Pointer(&sa[0])),
		uintptr(len(sa)),
	)
	if int32(r1) == -1 {
		return nil, fmt.Errorf("transport: bind RFCOMM channel %d: %w", channel, lastWSAError())
	}

	r1, _, _ = procListen.Call(socket, 16)
	if int32(r1) == -1 {
		return nil, fmt.Errorf("transport: listen RFCOMM channel %d: %w", channel, lastWSAError())
	}

	owned = false
	return &windowsRFCOMMListener{
		socket:  socket,
		channel: channel,
	}, nil
}

type windowsRFCOMMListener struct {
	socket  uintptr
	channel uint8
	closed  atomic.Bool
	once    sync.Once
}

func (l *windowsRFCOMMListener) Accept() (net.Conn, error) {
	for {
		if l.closed.Load() {
			return nil, net.ErrClosed
		}

		var remoteRaw [40]byte
		remoteLen := int32(len(remoteRaw))
		accepted, _, _ := procAccept.Call(
			l.socket,
			uintptr(unsafe.Pointer(&remoteRaw[0])),
			uintptr(unsafe.Pointer(&remoteLen)),
		)
		if accepted != ^uintptr(0) {
			if remoteLen < 16 {
				closeWindowsSocket(accepted)
				return nil, errors.New("transport: accepted truncated RFCOMM address")
			}

			var nonblocking uint32 = 1
			r1, _, _ := procIOCTLSocket.Call(
				accepted,
				windowsFIONBIO,
				uintptr(unsafe.Pointer(&nonblocking)),
			)
			if int32(r1) == -1 {
				err := lastWSAError()
				closeWindowsSocket(accepted)
				return nil, fmt.Errorf("transport: configure accepted RFCOMM socket: %w", err)
			}

			remote, err := windowsRFCOMMAddressFromSockaddr(remoteRaw, l.channel)
			if err != nil {
				closeWindowsSocket(accepted)
				return nil, err
			}
			return &windowsRFCOMMConn{
				socket: accepted,
				local:  rfcommAddr(fmt.Sprintf("*/%d", l.channel)),
				remote: rfcommAddr(remote),
			}, nil
		}

		err := lastWSAError()
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == windowsWSAEINTR {
			continue
		}
		if !errors.As(err, &errno) || errno != windowsWSAEWOULDBLOCK {
			if l.closed.Load() {
				return nil, net.ErrClosed
			}
			return nil, fmt.Errorf("transport: accept RFCOMM: %w", err)
		}

		if err := waitWindowsSocket(nil, l.socket, true, time.Time{}); err != nil {
			if l.closed.Load() {
				return nil, net.ErrClosed
			}
			return nil, fmt.Errorf("transport: wait for RFCOMM accept: %w", err)
		}
	}
}

func (l *windowsRFCOMMListener) Close() error {
	l.once.Do(func() {
		l.closed.Store(true)
		closeWindowsSocket(l.socket)
	})
	return nil
}

func (l *windowsRFCOMMListener) Addr() net.Addr {
	return rfcommAddr(fmt.Sprintf("*/%d", l.channel))
}

func windowsRFCOMMAddressFromSockaddr(raw [40]byte, channel uint8) (string, error) {
	if binary.LittleEndian.Uint16(raw[0:2]) != windowsAFBTH {
		return "", errors.New("transport: accepted non-RFCOMM Bluetooth address family")
	}
	if channel < 1 || channel > 30 {
		return "", errors.New("transport: accepted RFCOMM address has invalid listener channel")
	}
	var addr [6]uint8
	copy(addr[:], raw[8:14])
	return canonicalRFCOMMAddress(addr, channel), nil
}

var _ net.Listener = (*windowsRFCOMMListener)(nil)

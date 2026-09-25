//go:build windows

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsAFBTH          = 32
	windowsSockStream     = 1
	windowsBTHProtoRFCOMM = 3
	windowsFIONBIO        = 0x8004667e
	windowsSOLSocket      = 0xffff
	windowsSOError        = 0x1007

	windowsWSAEINTR       = 10004
	windowsWSAEWOULDBLOCK = 10035
	windowsWSAEINPROGRESS = 10036
	windowsWSAEALREADY    = 10037
)

var (
	winsockDLL        = windows.NewLazySystemDLL("ws2_32.dll")
	procWSAStartup    = winsockDLL.NewProc("WSAStartup")
	procWSASocket     = winsockDLL.NewProc("socket")
	procIOCTLSocket   = winsockDLL.NewProc("ioctlsocket")
	procConnect       = winsockDLL.NewProc("connect")
	procRecv          = winsockDLL.NewProc("recv")
	procSend          = winsockDLL.NewProc("send")
	procSelect        = winsockDLL.NewProc("select")
	procGetSockOpt    = winsockDLL.NewProc("getsockopt")
	procCloseSocket   = winsockDLL.NewProc("closesocket")
	procWSAGetLastErr = winsockDLL.NewProc("WSAGetLastError")

	winsockStartOnce sync.Once
	winsockStartErr  error
)

func ensureWinsock() error {
	winsockStartOnce.Do(func() {
		// WSADATA is 400 bytes on 32-bit Windows and 408 bytes on 64-bit
		// Windows. A larger aligned scratch buffer is safe for WSAStartup to
		// populate and avoids depending on private SDK struct definitions.
		var data [512]byte
		r1, _, _ := procWSAStartup.Call(0x0202, uintptr(unsafe.Pointer(&data[0])))
		if r1 != 0 {
			winsockStartErr = syscall.Errno(r1)
		}
	})
	return winsockStartErr
}

func dialRFCOMM(ctx context.Context, locator rfcommLocator) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ensureWinsock(); err != nil {
		return nil, fmt.Errorf("transport: initialize Winsock for RFCOMM: %w", err)
	}

	socket, _, _ := procWSASocket.Call(
		windowsAFBTH,
		windowsSockStream,
		windowsBTHProtoRFCOMM,
	)
	if socket == ^uintptr(0) {
		return nil, fmt.Errorf("transport: create Windows RFCOMM socket: %w", lastWSAError())
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
		return nil, fmt.Errorf("transport: configure Windows RFCOMM socket: %w", lastWSAError())
	}

	sa := windowsRFCOMMSockaddr(locator)
	r1, _, _ = procConnect.Call(
		socket,
		uintptr(unsafe.Pointer(&sa[0])),
		uintptr(len(sa)),
	)
	if int32(r1) == -1 {
		err := lastWSAError()
		if !isWindowsConnectPending(err) {
			return nil, fmt.Errorf("transport: connect RFCOMM %s: %w", locator.canonical, err)
		}
		if err := waitWindowsSocket(ctx, socket, false, time.Time{}); err != nil {
			return nil, fmt.Errorf("transport: connect RFCOMM %s: %w", locator.canonical, err)
		}
	}

	conn := &windowsRFCOMMConn{
		socket: socket,
		local:  rfcommAddr("local"),
		remote: rfcommAddr(locator.canonical),
	}
	owned = false
	return conn, nil
}

func windowsRFCOMMSockaddr(locator rfcommLocator) [40]byte {
	// SOCKADDR_BTH uses the Windows ABI layout:
	// USHORT addressFamily; 6 bytes padding; ULONGLONG btAddr;
	// GUID serviceClassId; ULONG port; 4 bytes trailing padding.
	var raw [40]byte
	raw[0] = windowsAFBTH
	copy(raw[8:14], locator.addr[:])
	raw[32] = locator.channel
	return raw
}

func isWindowsConnectPending(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == windowsWSAEWOULDBLOCK ||
		errno == windowsWSAEINPROGRESS ||
		errno == windowsWSAEALREADY
}

type windowsFDSet struct {
	Count  uint32
	Socket uintptr
	Rest   [63]uintptr
}

func newWindowsFDSet(socket uintptr) windowsFDSet {
	return windowsFDSet{Count: 1, Socket: socket}
}

type windowsTimeval struct {
	Sec  int32
	Usec int32
}

func windowsSelectTimeout(d time.Duration) windowsTimeval {
	if d < 0 {
		d = 0
	}
	micros := (d + time.Microsecond - 1) / time.Microsecond
	return windowsTimeval{
		Sec:  int32(micros / 1_000_000),
		Usec: int32(micros % 1_000_000),
	}
}

func waitWindowsSocket(ctx context.Context, socket uintptr, read bool, deadline time.Time) error {
	for {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
		}

		timeout := 100 * time.Millisecond
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return os.ErrDeadlineExceeded
			}
			if remaining < timeout {
				timeout = remaining
			}
		}
		if ctx != nil {
			if contextDeadline, ok := ctx.Deadline(); ok {
				remaining := time.Until(contextDeadline)
				if remaining <= 0 {
					return context.DeadlineExceeded
				}
				if remaining < timeout {
					timeout = remaining
				}
			}
		}

		ready := newWindowsFDSet(socket)
		except := newWindowsFDSet(socket)
		tv := windowsSelectTimeout(timeout)
		var readPtr, writePtr uintptr
		if read {
			readPtr = uintptr(unsafe.Pointer(&ready))
		} else {
			writePtr = uintptr(unsafe.Pointer(&ready))
		}
		r1, _, _ := procSelect.Call(
			0,
			readPtr,
			writePtr,
			uintptr(unsafe.Pointer(&except)),
			uintptr(unsafe.Pointer(&tv)),
		)
		if int32(r1) == -1 {
			err := lastWSAError()
			var errno syscall.Errno
			if errors.As(err, &errno) && errno == windowsWSAEINTR {
				continue
			}
			return err
		}
		if r1 == 0 {
			continue
		}
		if err := windowsSocketError(socket); err != nil {
			return err
		}
		return nil
	}
}

func windowsSocketError(socket uintptr) error {
	var value int32
	length := int32(unsafe.Sizeof(value))
	r1, _, _ := procGetSockOpt.Call(
		socket,
		windowsSOLSocket,
		windowsSOError,
		uintptr(unsafe.Pointer(&value)),
		uintptr(unsafe.Pointer(&length)),
	)
	if int32(r1) == -1 {
		return lastWSAError()
	}
	if value != 0 {
		return syscall.Errno(value)
	}
	return nil
}

func lastWSAError() error {
	r1, _, _ := procWSAGetLastErr.Call()
	if r1 == 0 {
		return syscall.EINVAL
	}
	return syscall.Errno(r1)
}

func closeWindowsSocket(socket uintptr) {
	_, _, _ = procCloseSocket.Call(socket)
}

type windowsRFCOMMConn struct {
	socket uintptr
	local  rfcommAddr
	remote rfcommAddr

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
	closed        atomic.Bool
	closeOnce     sync.Once
}

func (c *windowsRFCOMMConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		r1, _, _ := procRecv.Call(
			c.socket,
			uintptr(unsafe.Pointer(&p[0])),
			uintptr(len(p)),
			0,
		)
		if int32(r1) != -1 {
			if r1 == 0 {
				return 0, io.EOF
			}
			return int(r1), nil
		}
		err := lastWSAError()
		var errno syscall.Errno
		if !errors.As(err, &errno) || errno != windowsWSAEWOULDBLOCK {
			if c.closed.Load() {
				return 0, net.ErrClosed
			}
			return 0, os.NewSyscallError("recv", err)
		}
		if err := waitWindowsSocket(nil, c.socket, true, c.getReadDeadline()); err != nil {
			if c.closed.Load() {
				return 0, net.ErrClosed
			}
			return 0, err
		}
	}
}

func (c *windowsRFCOMMConn) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		if c.closed.Load() {
			if written > 0 {
				return written, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		r1, _, _ := procSend.Call(
			c.socket,
			uintptr(unsafe.Pointer(&p[written])),
			uintptr(len(p)-written),
			0,
		)
		if int32(r1) != -1 {
			if r1 == 0 {
				return written, io.ErrUnexpectedEOF
			}
			written += int(r1)
			continue
		}
		err := lastWSAError()
		var errno syscall.Errno
		if !errors.As(err, &errno) || errno != windowsWSAEWOULDBLOCK {
			if c.closed.Load() {
				return written, net.ErrClosed
			}
			return written, os.NewSyscallError("send", err)
		}
		if err := waitWindowsSocket(nil, c.socket, false, c.getWriteDeadline()); err != nil {
			if c.closed.Load() {
				return written, net.ErrClosed
			}
			return written, err
		}
	}
	return written, nil
}

func (c *windowsRFCOMMConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		closeWindowsSocket(c.socket)
	})
	return nil
}

func (c *windowsRFCOMMConn) LocalAddr() net.Addr  { return c.local }
func (c *windowsRFCOMMConn) RemoteAddr() net.Addr { return c.remote }

func (c *windowsRFCOMMConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *windowsRFCOMMConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *windowsRFCOMMConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *windowsRFCOMMConn) getReadDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.readDeadline
}

func (c *windowsRFCOMMConn) getWriteDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.writeDeadline
}

var _ Conn = (*windowsRFCOMMConn)(nil)

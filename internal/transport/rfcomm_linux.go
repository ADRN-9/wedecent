//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func dialRFCOMM(ctx context.Context, locator rfcommLocator) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(
		unix.AF_BLUETOOTH,
		unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		unix.BTPROTO_RFCOMM,
	)
	if err != nil {
		return nil, fmt.Errorf("transport: create RFCOMM socket: %w", err)
	}
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(fd)
		}
	}()

	sa := &unix.SockaddrRFCOMM{Addr: locator.addr, Channel: locator.channel}
	if err := unix.Connect(fd, sa); err != nil {
		if !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.EALREADY) && !errors.Is(err, unix.EINTR) {
			return nil, fmt.Errorf("transport: connect RFCOMM %s: %w", locator.canonical, err)
		}
		if err := waitRFCOMMConnect(ctx, fd); err != nil {
			return nil, fmt.Errorf("transport: connect RFCOMM %s: %w", locator.canonical, err)
		}
	}

	file := os.NewFile(uintptr(fd), "wedecent-rfcomm")
	if file == nil {
		return nil, errors.New("transport: wrap RFCOMM socket")
	}
	owned = false
	return &rfcommConn{
		file:   file,
		local:  rfcommAddr("local"),
		remote: rfcommAddr(locator.canonical),
	}, nil
}

func waitRFCOMMConnect(ctx context.Context, fd int) error {
	pollfd := []unix.PollFd{{
		Fd:     int32(fd),
		Events: unix.POLLOUT | unix.POLLERR | unix.POLLHUP,
	}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		timeout := 100 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return context.DeadlineExceeded
			}
			if remaining < timeout {
				timeout = remaining
			}
		}
		timeoutMS := int((timeout + time.Millisecond - 1) / time.Millisecond)
		n, err := unix.Poll(pollfd, timeoutMS)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if pollfd[0].Revents&unix.POLLNVAL != 0 {
			return syscall.EBADF
		}
		soerr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return err
		}
		if soerr == 0 {
			return nil
		}
		if syscall.Errno(soerr) == unix.EINPROGRESS || syscall.Errno(soerr) == unix.EALREADY {
			continue
		}
		return syscall.Errno(soerr)
	}
}

type rfcommConn struct {
	file   *os.File
	local  rfcommAddr
	remote rfcommAddr
}

func (c *rfcommConn) Read(p []byte) (int, error)         { return c.file.Read(p) }
func (c *rfcommConn) Write(p []byte) (int, error)        { return c.file.Write(p) }
func (c *rfcommConn) Close() error                       { return c.file.Close() }
func (c *rfcommConn) LocalAddr() net.Addr                { return c.local }
func (c *rfcommConn) RemoteAddr() net.Addr               { return c.remote }
func (c *rfcommConn) SetDeadline(t time.Time) error      { return c.file.SetDeadline(t) }
func (c *rfcommConn) SetReadDeadline(t time.Time) error  { return c.file.SetReadDeadline(t) }
func (c *rfcommConn) SetWriteDeadline(t time.Time) error { return c.file.SetWriteDeadline(t) }

var _ Conn = (*rfcommConn)(nil)

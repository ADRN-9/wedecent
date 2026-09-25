//go:build linux

package transport

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

func listenRFCOMM(channel uint8) (net.Listener, error) {
	fd, err := unix.Socket(
		unix.AF_BLUETOOTH,
		unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		unix.BTPROTO_RFCOMM,
	)
	if err != nil {
		return nil, fmt.Errorf("transport: create RFCOMM listener socket: %w", err)
	}
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(fd)
		}
	}()

	if err := unix.Bind(fd, &unix.SockaddrRFCOMM{Channel: channel}); err != nil {
		return nil, fmt.Errorf("transport: bind RFCOMM channel %d: %w", channel, err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		return nil, fmt.Errorf("transport: listen RFCOMM channel %d: %w", channel, err)
	}

	owned = false
	return &rfcommListener{
		fd:      fd,
		channel: channel,
	}, nil
}

type rfcommListener struct {
	fd      int
	channel uint8
	closed  atomic.Bool
	once    sync.Once
}

func (l *rfcommListener) Accept() (net.Conn, error) {
	for {
		if l.closed.Load() {
			return nil, net.ErrClosed
		}
		fd, sockaddr, err := unix.Accept4(
			l.fd,
			unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		)
		if err == nil {
			remote, ok := sockaddr.(*unix.SockaddrRFCOMM)
			if !ok {
				_ = unix.Close(fd)
				return nil, errors.New("transport: accepted non-RFCOMM socket")
			}
			file := os.NewFile(uintptr(fd), "wedecent-rfcomm-accepted")
			if file == nil {
				_ = unix.Close(fd)
				return nil, errors.New("transport: wrap accepted RFCOMM socket")
			}
			return &rfcommConn{
				file:   file,
				local:  rfcommAddr(fmt.Sprintf("*/%d", l.channel)),
				remote: rfcommAddr(canonicalRFCOMMAddress(remote.Addr, remote.Channel)),
			}, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			if l.closed.Load() || errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINVAL) {
				return nil, net.ErrClosed
			}
			return nil, fmt.Errorf("transport: accept RFCOMM: %w", err)
		}

		pollfd := []unix.PollFd{{
			Fd:     int32(l.fd),
			Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP,
		}}
		_, pollErr := unix.Poll(pollfd, 100)
		if errors.Is(pollErr, unix.EINTR) {
			continue
		}
		if pollErr != nil {
			if l.closed.Load() || errors.Is(pollErr, unix.EBADF) {
				return nil, net.ErrClosed
			}
			return nil, fmt.Errorf("transport: poll RFCOMM listener: %w", pollErr)
		}
		if l.closed.Load() {
			return nil, net.ErrClosed
		}
	}
}

func (l *rfcommListener) Close() error {
	var err error
	l.once.Do(func() {
		l.closed.Store(true)
		err = unix.Close(l.fd)
	})
	return err
}

func (l *rfcommListener) Addr() net.Addr {
	return rfcommAddr(fmt.Sprintf("*/%d", l.channel))
}

var _ net.Listener = (*rfcommListener)(nil)

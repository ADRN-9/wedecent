//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type serialConn struct {
	file     *os.File
	path     string
	original unix.Termios
	closeMu  sync.Mutex
	closed   bool
}

func dialSerial(ctx context.Context, path string, baud int) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("transport: open serial device: %w", err)
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("transport: stat serial device: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR {
		return nil, errors.New("transport: serial endpoint is not a character device")
	}

	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("transport: serial endpoint is not a configurable TTY: %w", err)
	}
	original := *termios
	if err := configureSerialTermios(termios, baud); err != nil {
		return nil, err
	}
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, termios); err != nil {
		return nil, fmt.Errorf("transport: configure serial device: %w", err)
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, &original)
		return nil, errors.New("transport: create serial file")
	}
	closeFD = false

	conn := &serialConn{file: file, path: path, original: original}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("transport: serial device does not support deadlines: %w", err)
	}
	return conn, nil
}

func configureSerialTermios(termios *unix.Termios, baud int) error {
	if termios == nil {
		return errors.New("transport: nil serial termios")
	}
	if baud != defaultSerialBaud {
		return errors.New("transport: unsupported serial baud")
	}
	termios.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	termios.Oflag &^= unix.OPOST
	termios.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	termios.Cflag &^= unix.CSIZE | unix.PARENB | unix.CSTOPB | unix.CRTSCTS | unix.CBAUD
	termios.Cflag |= unix.CS8 | unix.CLOCAL | unix.CREAD | unix.B115200
	termios.Ispeed = unix.B115200
	termios.Ospeed = unix.B115200
	termios.Cc[unix.VMIN] = 1
	termios.Cc[unix.VTIME] = 0
	return nil
}

func (c *serialConn) Read(p []byte) (int, error)  { return c.file.Read(p) }
func (c *serialConn) Write(p []byte) (int, error) { return c.file.Write(p) }

func (c *serialConn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	fd := int(c.file.Fd())
	_ = unix.IoctlSetTermios(fd, unix.TCSETS, &c.original)
	return c.file.Close()
}

func (c *serialConn) LocalAddr() net.Addr  { return serialAddr("local") }
func (c *serialConn) RemoteAddr() net.Addr { return serialAddr(c.path) }
func (c *serialConn) SetDeadline(t time.Time) error {
	return c.file.SetDeadline(t)
}
func (c *serialConn) SetReadDeadline(t time.Time) error {
	return c.file.SetReadDeadline(t)
}
func (c *serialConn) SetWriteDeadline(t time.Time) error {
	return c.file.SetWriteDeadline(t)
}

var _ Conn = (*serialConn)(nil)

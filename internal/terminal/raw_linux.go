//go:build linux

package terminal

import (
	"os"
	"syscall"
	"unsafe"
)

type RawState struct{ termios syscall.Termios }

func IsTerminal(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)))
	return errno == 0
}

func MakeRaw(f *os.File) (*RawState, error) {
	var old syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&old)))
	if errno != 0 {
		return nil, errno
	}
	raw := old
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&raw)))
	if errno != 0 {
		return nil, errno
	}
	return &RawState{termios: old}, nil
}

func Restore(f *os.File, state *RawState) error {
	if state == nil {
		return nil
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&state.termios)))
	if errno != 0 {
		return errno
	}
	return nil
}

func Size(f *os.File) (cols, rows uint16, err error) {
	var ws winsize
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return 0, 0, errno
	}
	return ws.Col, ws.Row, nil
}

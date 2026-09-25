//go:build darwin

package terminal

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const darwinPTYNameSize = 128

func Start(shell string, cols, rows uint16, term string) (*PTY, error) {
	if shell == "" {
		shell = "/bin/sh"
	}
	if shell[0] != '/' {
		return nil, errors.New("shell must be an absolute path")
	}
	master, slave, err := openDarwinPTY()
	if err != nil {
		return nil, err
	}
	defer slave.Close()
	if err := setDarwinWinsize(master.Fd(), cols, rows); err != nil {
		master.Close()
		return nil, err
	}

	cmd := exec.Command(shell)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = append(os.Environ(), "TERM="+safeDarwinTerm(term))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		master.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}

	return &PTY{
		reader: master,
		writer: master,
		resize: func(cols, rows uint16) error { return setDarwinWinsize(master.Fd(), cols, rows) },
		wait:   cmd.Wait,
		close: func() error {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(syscall.SIGHUP)
			}
			return master.Close()
		},
	}, nil
}

func openDarwinPTY() (*os.File, *os.File, error) {
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	master := os.NewFile(uintptr(fd), "/dev/ptmx")
	if master == nil {
		syscall.Close(fd)
		return nil, nil, errors.New("create PTY master file")
	}
	fail := func(err error) (*os.File, *os.File, error) {
		master.Close()
		return nil, nil, err
	}

	slavePath, err := darwinPTYName(master.Fd())
	if err != nil {
		return fail(fmt.Errorf("get PTY slave name: %w", err))
	}
	if err := darwinPTYIoctl(master.Fd(), syscall.TIOCPTYGRANT, nil); err != nil {
		return fail(fmt.Errorf("grant PTY slave: %w", err))
	}
	if err := darwinPTYIoctl(master.Fd(), syscall.TIOCPTYUNLK, nil); err != nil {
		return fail(fmt.Errorf("unlock PTY slave: %w", err))
	}

	sfd, err := syscall.Open(slavePath, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fail(fmt.Errorf("open PTY slave: %w", err))
	}
	slave := os.NewFile(uintptr(sfd), slavePath)
	if slave == nil {
		syscall.Close(sfd)
		return fail(errors.New("create PTY slave file"))
	}
	return master, slave, nil
}

func darwinPTYName(fd uintptr) (string, error) {
	var name [darwinPTYNameSize]byte
	if err := darwinPTYIoctl(fd, syscall.TIOCPTYGNAME, unsafe.Pointer(&name[0])); err != nil {
		return "", err
	}
	for i, b := range name {
		if b == 0 {
			if i == 0 {
				return "", errors.New("PTY slave name is empty")
			}
			return string(name[:i]), nil
		}
	}
	return "", errors.New("PTY slave name is not NUL-terminated")
}

func darwinPTYIoctl(fd uintptr, request uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func setDarwinWinsize(fd uintptr, cols, rows uint16) error {
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	return unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
}

func safeDarwinTerm(term string) string {
	switch term {
	case "xterm", "xterm-256color", "screen", "screen-256color", "vt100":
		return term
	default:
		return "xterm-256color"
	}
}

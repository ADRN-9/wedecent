//go:build linux

package terminal

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func Start(shell string, cols, rows uint16, term string) (*PTY, error) {
	if shell == "" {
		shell = "/bin/sh"
	}
	if shell[0] != '/' {
		return nil, errors.New("shell must be an absolute path")
	}
	master, slave, err := openPTY()
	if err != nil {
		return nil, err
	}
	defer slave.Close()
	if err := setWinsize(master.Fd(), cols, rows); err != nil {
		master.Close()
		return nil, err
	}

	cmd := exec.Command(shell)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = append(os.Environ(), "TERM="+safeTerm(term))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		master.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}

	return &PTY{
		reader: master,
		writer: master,
		resize: func(cols, rows uint16) error { return setWinsize(master.Fd(), cols, rows) },
		wait:   cmd.Wait,
		close: func() error {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(syscall.SIGHUP)
			}
			return master.Close()
		},
	}, nil
}

func openPTY() (*os.File, *os.File, error) {
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	master := os.NewFile(uintptr(fd), "/dev/ptmx")
	if master == nil {
		syscall.Close(fd)
		return nil, nil, errors.New("create PTY master file")
	}
	unlock := int32(0)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		master.Close()
		return nil, nil, fmt.Errorf("unlock PTY: %w", errno)
	}
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TIOCGPTN), uintptr(unsafe.Pointer(&n))); errno != 0 {
		master.Close()
		return nil, nil, fmt.Errorf("get PTY number: %w", errno)
	}
	slavePath := "/dev/pts/" + strconv.FormatUint(uint64(n), 10)
	sfd, err := syscall.Open(slavePath, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("open PTY slave: %w", err)
	}
	slave := os.NewFile(uintptr(sfd), slavePath)
	if slave == nil {
		syscall.Close(sfd)
		master.Close()
		return nil, nil, errors.New("create PTY slave file")
	}
	return master, slave, nil
}

func setWinsize(fd uintptr, cols, rows uint16) error {
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	ws := &winsize{Row: rows, Col: cols}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
	if errno != 0 {
		return errno
	}
	return nil
}

func safeTerm(term string) string {
	switch term {
	case "xterm", "xterm-256color", "screen", "screen-256color", "vt100", "linux":
		return term
	default:
		return "xterm-256color"
	}
}

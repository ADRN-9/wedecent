//go:build darwin

package terminal

import (
	"os"

	"golang.org/x/sys/unix"
)

type RawState struct{ termios unix.Termios }

func IsTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	return err == nil
}

func MakeRaw(f *os.File) (*RawState, error) {
	old, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETA, &raw); err != nil {
		return nil, err
	}
	return &RawState{termios: *old}, nil
}

func Restore(f *os.File, state *RawState) error {
	if state == nil {
		return nil
	}
	return unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETA, &state.termios)
}

func Size(f *os.File) (cols, rows uint16, err error) {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0, err
	}
	return ws.Col, ws.Row, nil
}

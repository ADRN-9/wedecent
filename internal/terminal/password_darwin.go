//go:build darwin

package terminal

import (
	"bufio"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func ReadPassword(f *os.File) (string, error) {
	old, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	if err != nil {
		return "", err
	}
	noEcho := *old
	noEcho.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETA, &noEcho); err != nil {
		return "", err
	}
	defer func() {
		_ = unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETA, old)
	}()
	line, err := bufio.NewReader(f).ReadString('\n')
	return strings.TrimSpace(line), err
}

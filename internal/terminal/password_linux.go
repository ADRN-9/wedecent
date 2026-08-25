//go:build linux

package terminal

import (
	"bufio"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func ReadPassword(f *os.File) (string, error) {
	var old syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&old)))
	if errno != 0 {
		return "", errno
	}
	noEcho := old
	noEcho.Lflag &^= syscall.ECHO
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&noEcho)))
	if errno != 0 {
		return "", errno
	}
	defer func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&old)))
	}()
	line, err := bufio.NewReader(f).ReadString('\n')
	return strings.TrimSpace(line), err
}

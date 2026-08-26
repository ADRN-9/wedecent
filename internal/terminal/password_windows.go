//go:build windows

package terminal

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const enableEchoInput = 0x0004

var (
	kernel32Console    = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32Console.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32Console.NewProc("SetConsoleMode")
)

func ReadPassword(f *os.File) (string, error) {
	handle := syscall.Handle(f.Fd())
	var oldMode uint32
	ok, _, callErr := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&oldMode)))
	if ok == 0 {
		return "", fmt.Errorf("get console mode: %w", callErr)
	}
	noEcho := oldMode &^ enableEchoInput
	ok, _, callErr = procSetConsoleMode.Call(uintptr(handle), uintptr(noEcho))
	if ok == 0 {
		return "", fmt.Errorf("disable console echo: %w", callErr)
	}
	defer func() {
		_, _, _ = procSetConsoleMode.Call(uintptr(handle), uintptr(oldMode))
	}()

	line, err := bufio.NewReader(f).ReadString('\n')
	return strings.TrimSpace(line), err
}

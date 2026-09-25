//go:build windows

package terminal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	procThreadAttributePseudoConsole = 0x00020016
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procCreatePseudoConsole = kernel32.NewProc("CreatePseudoConsole")
	procResizePseudoConsole = kernel32.NewProc("ResizePseudoConsole")
	procClosePseudoConsole  = kernel32.NewProc("ClosePseudoConsole")
)

type windowsExitError struct{ code uint32 }

func (e windowsExitError) Error() string { return fmt.Sprintf("process exited with code %d", e.code) }
func (e windowsExitError) ExitCode() int { return int(e.code) }

func Start(shell string, cols, rows uint16, _ string) (*PTY, error) {
	if shell == "" {
		shell = defaultWindowsShell()
	}
	if !filepath.IsAbs(shell) {
		return nil, errors.New("shell must be an absolute path")
	}
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create ConPTY input pipe: %w", err)
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		inputRead.Close()
		inputWrite.Close()
		return nil, fmt.Errorf("create ConPTY output pipe: %w", err)
	}

	cleanupPipes := func() {
		_ = inputRead.Close()
		_ = inputWrite.Close()
		_ = outputRead.Close()
		_ = outputWrite.Close()
	}

	var hpc uintptr
	hr, _, _ := procCreatePseudoConsole.Call(
		uintptr(packCoord(cols, rows)),
		inputRead.Fd(),
		outputWrite.Fd(),
		0,
		uintptr(unsafe.Pointer(&hpc)),
	)
	if failedHRESULT(hr) {
		cleanupPipes()
		return nil, fmt.Errorf("CreatePseudoConsole failed: HRESULT 0x%08x", uint32(hr))
	}

	// CreatePseudoConsole duplicates the PTY-side pipe handles into the console
	// host. Release this process's copies immediately, matching Microsoft's
	// documented ConPTY lifecycle; retain only the host-side read/write ends.
	_ = inputRead.Close()
	_ = outputWrite.Close()

	attrList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		procClosePseudoConsole.Call(hpc)
		_ = inputWrite.Close()
		_ = outputRead.Close()
		return nil, fmt.Errorf("allocate ConPTY process attribute list: %w", err)
	}
	defer attrList.Delete()

	if err := attrList.Update(
		procThreadAttributePseudoConsole,
		unsafe.Pointer(hpc),
		unsafe.Sizeof(hpc),
	); err != nil {
		procClosePseudoConsole.Call(hpc)
		_ = inputWrite.Close()
		_ = outputRead.Close()
		return nil, fmt.Errorf("set ConPTY process attribute: %w", err)
	}

	si := windows.StartupInfoEx{
		ProcThreadAttributeList: attrList.List(),
	}
	si.Cb = uint32(unsafe.Sizeof(si))
	// A console parent can otherwise have its standard handles duplicated into
	// the child even when bInheritHandles is false. Explicit null standard
	// handles prevent those parent-console streams from bypassing the ConPTY;
	// the pseudoconsole attribute supplies the child's console attachment.
	si.Flags = windows.STARTF_USESTDHANDLES

	cmdLine, err := windows.UTF16PtrFromString(syscall.EscapeArg(shell))
	if err != nil {
		procClosePseudoConsole.Call(hpc)
		_ = inputWrite.Close()
		_ = outputRead.Close()
		return nil, fmt.Errorf("encode shell path: %w", err)
	}

	var pi windows.ProcessInformation
	err = windows.CreateProcess(
		nil,
		cmdLine,
		nil,
		nil,
		false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		nil,
		nil,
		&si.StartupInfo,
		&pi,
	)
	if err != nil {
		procClosePseudoConsole.Call(hpc)
		_ = inputWrite.Close()
		_ = outputRead.Close()
		return nil, fmt.Errorf("start shell with ConPTY: %w", err)
	}
	_ = windows.CloseHandle(pi.Thread)

	p := &PTY{
		reader: outputRead,
		writer: inputWrite,
	}
	p.resize = func(cols, rows uint16) error {
		if cols == 0 {
			cols = 80
		}
		if rows == 0 {
			rows = 24
		}
		hr, _, _ := procResizePseudoConsole.Call(hpc, uintptr(packCoord(cols, rows)))
		if failedHRESULT(hr) {
			return fmt.Errorf("ResizePseudoConsole failed: HRESULT 0x%08x", uint32(hr))
		}
		return nil
	}
	p.wait = func() error {
		if _, err := windows.WaitForSingleObject(pi.Process, windows.INFINITE); err != nil {
			return err
		}
		var code uint32
		if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
			return err
		}
		if code != 0 {
			return windowsExitError{code: code}
		}
		return nil
	}
	p.close = func() error {
		_ = inputWrite.Close()
		_ = outputRead.Close()
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
		procClosePseudoConsole.Call(hpc)
		return nil
	}
	return p, nil
}

func packCoord(cols, rows uint16) uint32 {
	return uint32(cols) | uint32(rows)<<16
}

func failedHRESULT(v uintptr) bool {
	return int32(uint32(v)) < 0
}

func defaultWindowsShell() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

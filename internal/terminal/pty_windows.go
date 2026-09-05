//go:build windows

package terminal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	extendedStartupInfoPresent       = 0x00080000
	createUnicodeEnvironment         = 0x00000400
	procThreadAttributePseudoConsole = 0x00020016
	infinite                         = 0xFFFFFFFF
)

var (
	kernel32                          = syscall.NewLazyDLL("kernel32.dll")
	procCreatePseudoConsole           = kernel32.NewProc("CreatePseudoConsole")
	procResizePseudoConsole           = kernel32.NewProc("ResizePseudoConsole")
	procClosePseudoConsole            = kernel32.NewProc("ClosePseudoConsole")
	procInitializeProcThreadAttrList  = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute     = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList = kernel32.NewProc("DeleteProcThreadAttributeList")
)

type startupInfoEx struct {
	StartupInfo   syscall.StartupInfo
	AttributeList *byte
}

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
	_ = inputRead.Close()
	_ = outputWrite.Close()

	attrList, err := newPseudoConsoleAttributeList(hpc)
	if err != nil {
		procClosePseudoConsole.Call(hpc)
		_ = inputWrite.Close()
		_ = outputRead.Close()
		return nil, err
	}

	si := startupInfoEx{AttributeList: attrList.ptr}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(si))
	cmdLine, err := syscall.UTF16PtrFromString(syscall.EscapeArg(shell))
	if err != nil {
		attrList.close()
		procClosePseudoConsole.Call(hpc)
		_ = inputWrite.Close()
		_ = outputRead.Close()
		return nil, fmt.Errorf("encode shell path: %w", err)
	}

	var pi syscall.ProcessInformation
	err = syscall.CreateProcess(
		nil,
		cmdLine,
		nil,
		nil,
		false,
		extendedStartupInfoPresent|createUnicodeEnvironment,
		nil,
		nil,
		&si.StartupInfo,
		&pi,
	)
	attrList.close()
	if err != nil {
		procClosePseudoConsole.Call(hpc)
		_ = inputWrite.Close()
		_ = outputRead.Close()
		return nil, fmt.Errorf("start shell with ConPTY: %w", err)
	}
	_ = syscall.CloseHandle(pi.Thread)

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
		if _, err := syscall.WaitForSingleObject(pi.Process, infinite); err != nil {
			return err
		}
		var code uint32
		if err := syscall.GetExitCodeProcess(pi.Process, &code); err != nil {
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
		_ = syscall.TerminateProcess(pi.Process, 1)
		_ = syscall.CloseHandle(pi.Process)
		procClosePseudoConsole.Call(hpc)
		return nil
	}
	return p, nil
}

type attributeList struct {
	storage []byte
	ptr     *byte
}

func newPseudoConsoleAttributeList(hpc uintptr) (*attributeList, error) {
	var size uintptr
	procInitializeProcThreadAttrList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return nil, errors.New("InitializeProcThreadAttributeList returned zero size")
	}
	storage := make([]byte, size)
	ptr := &storage[0]
	ok, _, err := procInitializeProcThreadAttrList.Call(
		uintptr(unsafe.Pointer(ptr)),
		1,
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if ok == 0 {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %w", err)
	}
	ok, _, err = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(ptr)),
		0,
		procThreadAttributePseudoConsole,
		hpc,
		unsafe.Sizeof(hpc),
		0,
		0,
	)
	if ok == 0 {
		procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(ptr)))
		return nil, fmt.Errorf("UpdateProcThreadAttribute: %w", err)
	}
	return &attributeList{storage: storage, ptr: ptr}, nil
}

func (a *attributeList) close() {
	if a == nil || a.ptr == nil {
		return
	}
	procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(a.ptr)))
	a.ptr = nil
	a.storage = nil
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

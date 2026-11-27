//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"wedecent.com/wedecent/internal/updateinfo"
)

var shell32Update = syscall.NewLazyDLL("shell32.dll")
var shellExecuteExUpdate = shell32Update.NewProc("ShellExecuteExW")

type shellExecuteInfo struct {
	Size          uint32
	Mask          uint32
	Window        windows.Handle
	Verb          *uint16
	File          *uint16
	Parameters    *uint16
	Directory     *uint16
	Show          int32
	Instance      windows.Handle
	IDList        uintptr
	Class         *uint16
	ClassKey      windows.Handle
	HotKey        uint32
	IconOrMonitor windows.Handle
	Process       windows.Handle
}

func runUpdateCommand(args []string) error {
	if len(args) == 0 || args[0] != "apply" {
		return errors.New("usage: wd-agent update apply")
	}
	if len(args) == 1 {
		if err := updateinfo.ValidateInstalledUpdateLauncher(); err != nil {
			return err
		}
		if currentAgentProcessElevated() {
			return updateinfo.ApplyInstalledWindowsStable(context.Background())
		}
		return launchElevatedStableUpdate()
	}
	if len(args) == 2 && args[1] == "--elevated" {
		if !currentAgentProcessElevated() {
			return errors.New("elevated updater helper requires administrator consent")
		}
		return updateinfo.ApplyInstalledWindowsStable(context.Background())
	}
	return errors.New("update apply accepts no caller-supplied paths or trust material")
}

func launchElevatedStableUpdate() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve installed updater executable")
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return fmt.Errorf("resolve installed updater path")
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return fmt.Errorf("encode updater executable")
	}
	parameters, _ := syscall.UTF16PtrFromString("update apply --elevated")
	directory, err := syscall.UTF16PtrFromString(filepath.Dir(executable))
	if err != nil {
		return fmt.Errorf("encode updater working directory")
	}
	info := shellExecuteInfo{
		Size: uint32(unsafe.Sizeof(shellExecuteInfo{})),
		Mask: 0x00000040, Verb: verb, File: file,
		Parameters: parameters, Directory: directory, Show: 0,
	}
	ok, _, callErr := shellExecuteExUpdate.Call(uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		if callErr != syscall.Errno(0) {
			return fmt.Errorf("Windows elevation request was denied or failed: %w", callErr)
		}
		return errors.New("Windows elevation request was denied or failed")
	}
	if info.Process == 0 {
		return errors.New("Windows elevation helper did not return a process handle")
	}
	defer windows.CloseHandle(info.Process)
	wait, err := windows.WaitForSingleObject(info.Process, windows.INFINITE)
	if err != nil || wait != windows.WAIT_OBJECT_0 {
		return errors.New("wait for elevated updater helper failed")
	}
	var exitCode uint32
	if err := windows.GetExitCodeProcess(info.Process, &exitCode); err != nil {
		return fmt.Errorf("read elevated updater exit status")
	}
	if exitCode != 0 {
		return fmt.Errorf("elevated updater failed with exit code %d", exitCode)
	}
	return nil
}

func currentAgentProcessElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

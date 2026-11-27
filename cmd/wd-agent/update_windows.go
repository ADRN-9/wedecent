//go:build windows

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	if len(args) < 1 || args[0] != "apply" {
		return errors.New("usage: wd-agent update apply")
	}
	if len(args) == 1 {
		if err := updateinfo.ValidateInstalledUpdateLauncher(); err != nil {
			return err
		}
		if currentAgentProcessElevated() {
			return launchStagedUpdateWorker(0)
		}
		return launchElevatedStableUpdate(uint32(os.Getpid()))
	}
	if len(args) == 3 && args[1] == "--wait-for-ui" {
		pid, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil || pid == 0 {
			return errors.New("invalid desktop process identity")
		}
		if err := updateinfo.ValidateInstalledUpdateLauncher(); err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return errors.New("resolve installed updater executable")
		}
		installDir := filepath.Dir(executable)
		if err := waitForProductProcess(uint32(pid), filepath.Join(installDir, "wd-ui.exe")); err != nil {
			return fmt.Errorf("wait for desktop shutdown: %w", err)
		}
		if currentAgentProcessElevated() {
			return launchStagedUpdateWorker(0)
		}
		return launchElevatedStableUpdate(uint32(os.Getpid()))
	}
	if len(args) == 2 && args[1] == "--elevated" {
		if !currentAgentProcessElevated() {
			return errors.New("elevated updater helper requires administrator consent")
		}
		if err := updateinfo.ValidateInstalledUpdateLauncher(); err != nil {
			return err
		}
		return launchStagedUpdateWorker(0)
	}
	if len(args) == 4 && args[1] == "--elevated" && args[2] == "--launcher-pid" {
		pid, err := strconv.ParseUint(args[3], 10, 32)
		if err != nil || pid == 0 || !currentAgentProcessElevated() {
			return errors.New("invalid or unauthorized elevated launcher identity")
		}
		if err := updateinfo.ValidateInstalledUpdateLauncher(); err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return errors.New("resolve installed updater executable")
		}
		if err := validateProcessImage(uint32(pid), executable); err != nil {
			return fmt.Errorf("authenticate unelevated update caller: %w", err)
		}
		return launchStagedUpdateWorker(uint32(pid))
	}
	if len(args) == 6 && args[1] == "--worker" && args[2] == "--parent-pid" && args[4] == "--launcher-pid" {
		parentPID, err1 := strconv.ParseUint(args[3], 10, 32)
		launcherPID, err2 := strconv.ParseUint(args[5], 10, 32)
		if err1 != nil || err2 != nil || parentPID == 0 || !currentAgentProcessElevated() {
			return errors.New("invalid or unauthorized update worker request")
		}
		if err := updateinfo.ValidateInstalledUpdateWorker(); err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return errors.New("resolve update worker executable")
		}
		installDir := filepath.Dir(filepath.Dir(executable))
		if err := waitForUpdateLaunchers(uint32(parentPID), uint32(launcherPID), filepath.Join(installDir, "wd-agent.exe")); err != nil {
			return fmt.Errorf("wait for authenticated updater launchers: %w", err)
		}
		err = updateinfo.ApplyInstalledWindowsStable(context.Background())
		writeUpdateApplyResult(err)
		return err
	}
	return errors.New("update apply accepts no caller-supplied paths or trust material")
}

func launchStagedUpdateWorker(launcherPID uint32) error {
	worker, err := updateinfo.PrepareWindowsUpdateWorker(context.Background())
	if err != nil {
		return err
	}
	cmd := exec.Command(worker, "update", "apply", "--worker", "--parent-pid",
		strconv.Itoa(os.Getpid()), "--launcher-pid", strconv.FormatUint(uint64(launcherPID), 10))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return errors.New("create update worker readiness pipe")
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start protected update worker: %w", err)
	}
	line, readErr := bufio.NewReader(stdout).ReadString('\n')
	if readErr != nil || line != "READY\n" {
		_ = cmd.Process.Kill()
		return errors.New("protected update worker did not authenticate both launcher processes")
	}
	return nil
}

func launchElevatedStableUpdate(launcherPID uint32) error {
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
	parametersText := "update apply --elevated"
	if launcherPID != 0 {
		parametersText += " --launcher-pid " + strconv.FormatUint(uint64(launcherPID), 10)
	}
	parameters, _ := syscall.UTF16PtrFromString(parametersText)
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

func waitForProductProcess(pid uint32, expectedImage string) error {
	handle, err := openExpectedProcess(pid, expectedImage)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	wait, err := windows.WaitForSingleObject(handle, windows.INFINITE)
	if err != nil || wait != windows.WAIT_OBJECT_0 {
		return errors.New("waiting for desktop process exit failed")
	}
	return nil
}

func waitForUpdateLaunchers(elevatedPID, callerPID uint32, expectedImage string) error {
	elevated, err := openExpectedProcess(elevatedPID, expectedImage)
	if err != nil {
		return fmt.Errorf("authenticate elevated launcher: %w", err)
	}
	defer windows.CloseHandle(elevated)
	var caller windows.Handle
	if callerPID != 0 {
		caller, err = openExpectedProcess(callerPID, expectedImage)
		if err != nil {
			return fmt.Errorf("authenticate original update caller: %w", err)
		}
		defer windows.CloseHandle(caller)
	}
	if _, err := fmt.Fprintln(os.Stdout, "READY"); err != nil {
		return errors.New("cannot acknowledge authenticated update worker")
	}
	wait, err := windows.WaitForSingleObject(elevated, windows.INFINITE)
	if err != nil || wait != windows.WAIT_OBJECT_0 {
		return errors.New("waiting for elevated launcher exit failed")
	}
	if caller != 0 {
		wait, err = windows.WaitForSingleObject(caller, windows.INFINITE)
		if err != nil || wait != windows.WAIT_OBJECT_0 {
			return errors.New("waiting for original update caller exit failed")
		}
	}
	return nil
}

func openExpectedProcess(pid uint32, expectedImage string) (windows.Handle, error) {
	process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, errors.New("open expected WeDecent process")
	}
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	query := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")
	ok, _, _ := query.Call(uintptr(process), 0,
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		_ = windows.CloseHandle(process)
		return 0, errors.New("query expected WeDecent process image")
	}
	actual, err := filepath.Abs(syscall.UTF16ToString(buffer[:size]))
	expected, expectedErr := filepath.Abs(expectedImage)
	if err != nil || expectedErr != nil ||
		!strings.EqualFold(filepath.Clean(actual), filepath.Clean(expected)) {
		_ = windows.CloseHandle(process)
		return 0, errors.New("process image does not match installed WeDecent executable")
	}
	return process, nil
}

func validateProcessImage(pid uint32, expectedImage string) error {
	handle, err := openExpectedProcess(pid, expectedImage)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

func writeUpdateApplyResult(err error) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return
	}
	path := filepath.Join(programData, "WeDecent", "update-apply.log")
	file, openErr := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if openErr != nil {
		return
	}
	defer file.Close()
	if err != nil {
		_, _ = fmt.Fprintf(file, "stable update failed: %v\n", err)
		return
	}
	_, _ = fmt.Fprintln(file, "stable update completed")
}

func currentAgentProcessElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

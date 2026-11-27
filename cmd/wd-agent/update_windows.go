//go:build windows

package main

import (
	"bufio"
	"context"
	"errors"
	"errors"
	"fmt"
	"io"
	"os"
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
			return launchStagedUpdateWorker()
		}
		return launchElevatedStableUpdate()
	}
	if len(args) == 3 && args[1] == "--wait-for-ui" {
		pid, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil || pid == 0 {
			return errors.New("invalid desktop process identity")
		}
		if err := updateinfo.ValidateInstalledUpdateLauncher(); err != nil {
			return err
		}
		installDir := filepath.Dir(mustCurrentExecutable())
		if err := waitForProductProcess(uint32(pid), filepath.Join(installDir, "wd-ui.exe"), false); err != nil {
			return fmt.Errorf("wait for desktop shutdown: %w", err)
		}
		if currentAgentProcessElevated() {
			return launchStagedUpdateWorker()
		}
		return launchElevatedStableUpdate()
	}
	if len(args) == 4 && args[1] == "--worker" && args[2] == "--parent-pid" {
		pid, err := strconv.ParseUint(args[3], 10, 32)
		if err != nil || pid == 0 || !currentAgentProcessElevated() {
			return errors.New("invalid or unauthorized update worker request")
		}
		if err := updateinfo.ValidateInstalledUpdateWorker(); err != nil {
			return err
		}
		installDir := filepath.Dir(filepath.Dir(mustCurrentExecutable()))
		if err := waitForProductProcess(uint32(pid), filepath.Join(installDir, "wd-agent.exe"), true); err != nil {
			return fmt.Errorf("wait for elevated launcher shutdown: %w", err)
		}
		err := updateinfo.ApplyInstalledWindowsStable(context.Background())
		writeUpdateApplyResult(err)
		return err
	}
	if len(args) == 2 && args[1] == "--elevated" {
		if !currentAgentProcessElevated() {
			return errors.New("elevated updater helper requires administrator consent")
		}
		if err := updateinfo.ValidateInstalledUpdateLauncher(); err != nil {
			return err
		}
		return launchStagedUpdateWorker()
	}
	return errors.New("update apply accepts no caller-supplied paths or trust material")
}

func mustCurrentExecutable() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path
}

func launchStagedUpdateWorker() error {
	worker, err := updateinfo.PrepareWindowsUpdateWorker(context.Background())
	if err != nil {
		return err
	}
	cmd := exec.Command(worker, "update", "apply", "--worker", "--parent-pid", strconv.Itoa(os.Getpid()))
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
		return errors.New("protected update worker did not authenticate its launcher")
	}
	return nil
}

func waitForProductProcess(pid uint32, expectedImage string, announceReady bool) error {
	process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open expected parent process")
	}
	defer windows.CloseHandle(process)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	query := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")
	ok, _, callErr := query.Call(
		uintptr(process), 0,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ok == 0 {
		return fmt.Errorf("query expected parent executable: %w", callErr)
	}
	actualImage := syscall.UTF16ToString(buffer[:size])
	actualImage, err = filepath.Abs(actualImage)
	if err != nil || !strings.EqualFold(filepath.Clean(actualImage), filepath.Clean(expectedImage)) {
		return errors.New("parent process image does not match the installed WeDecent executable")
	}
	if announceReady {
		if _, err := fmt.Fprintln(os.Stdout, "READY"); err != nil {
			return errors.New("cannot acknowledge authenticated update worker")
		}
	}
	wait, err := windows.WaitForSingleObject(process, windows.INFINITE)
	if err != nil || wait != windows.WAIT_OBJECT_0 {
		return errors.New("waiting for parent process exit failed")
	}
	return nil
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

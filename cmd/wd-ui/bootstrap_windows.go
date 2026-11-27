//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/guiapp"
)

const createNoWindow = 0x08000000

const th32csSnapProcess = 0x00000002

var (
	kernel32Core = syscall.NewLazyDLL("kernel32.dll")
	toolhelp32Core = syscall.NewLazyDLL("kernel32.dll")
	createToolhelpSnapshotCore = toolhelp32Core.NewProc("CreateToolhelp32Snapshot")
	process32FirstCore = toolhelp32Core.NewProc("Process32FirstW")
	process32NextCore = toolhelp32Core.NewProc("Process32NextW")
	queryProcessImageCore = kernel32Core.NewProc("QueryFullProcessImageNameW")
)

type processEntry32Core struct {
	Size uint32
	Usage uint32
	ProcessID uint32
	DefaultHeapID uintptr
	ModuleID uint32
	Threads uint32
	ParentProcessID uint32
	BasePriority int32
	Flags uint32
	ExeFile [260]uint16
}

var (
	localCoreProcessMu sync.Mutex
	localCoreProcess *exec.Cmd
	localCoreDone chan error
)

func prepareLocalCore(ctx context.Context, core *coreclient.Client) (guiapp.Core, error) {
	if err := ensureLocalCore(ctx, core, launchSiblingCore, defaultCoreBootstrapConfig); err != nil {
		return nil, err
	}
	recover := func(recoveryCtx context.Context) error {
		return ensureLocalCore(recoveryCtx, core, launchSiblingCore, defaultCoreBootstrapConfig)
	}
	return newRecoveringCore(core, recover), nil
}

func launchSiblingCore() (<-chan error, error) {
	path, err := siblingExecutablePath(os.Executable, filepath.EvalSymlinks, "wd-core.exe")
	if err != nil {
		return nil, ErrCoreLaunch
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrCoreLaunch
	}

	cmd := exec.Command(path)
	cmd.Dir = filepath.Dir(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	if err := cmd.Start(); err != nil {
		return nil, ErrCoreLaunch
	}

	done := make(chan error, 1)
	localCoreProcessMu.Lock()
	localCoreProcess = cmd
	localCoreDone = done
	localCoreProcessMu.Unlock()
	go func() {
		err := cmd.Wait()
		done <- err
		close(done)
		localCoreProcessMu.Lock()
		if localCoreProcess == cmd {
			localCoreProcess = nil
			localCoreDone = nil
		}
		localCoreProcessMu.Unlock()
	}()
	return done, nil
}

func stopSiblingCore() error {
	localCoreProcessMu.Lock()
	cmd, done := localCoreProcess, localCoreDone
	localCoreProcessMu.Unlock()
	if cmd != nil && cmd.Process != nil && done != nil {
		select {
		case <-done:
		default:
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return fmt.Errorf("stop Local Core before update: %w", err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				return errors.New("Local Core did not stop before update")
			}
		}
	}
	return stopInstalledCoreProcesses()
}

func stopInstalledCoreProcesses() error {
	executable, err := os.Executable()
	if err != nil {
		return errors.New("resolve desktop install directory")
	}
	expected, err := filepath.Abs(filepath.Join(filepath.Dir(executable), "wd-core.exe"))
	if err != nil {
		return errors.New("resolve installed Local Core path")
	}
	snapshot, _, callErr := createToolhelpSnapshotCore.Call(th32csSnapProcess, 0)
	if windows.Handle(snapshot) == windows.InvalidHandle {
		return fmt.Errorf("enumerate Local Core processes: %w", callErr)
	}
	defer windows.CloseHandle(windows.Handle(snapshot))
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		return errors.New("read desktop user identity")
	}
	entry := processEntry32Core{Size: uint32(unsafe.Sizeof(processEntry32Core{}))}
	ok, _, _ := process32FirstCore.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	for ok != 0 {
		if strings.EqualFold(syscall.UTF16ToString(entry.ExeFile[:]), "wd-core.exe") && entry.ProcessID != uint32(os.Getpid()) {
			process, openErr := windows.OpenProcess(
				windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE,
				false, entry.ProcessID,
			)
			if openErr != nil {
				return errors.New("cannot inspect a running Local Core process; update was not started")
			}
			imageBuffer := make([]uint16, 32768)
			imageSize := uint32(len(imageBuffer))
			queryOK, _, _ := queryProcessImageCore.Call(
				uintptr(process), 0, uintptr(unsafe.Pointer(&imageBuffer[0])),
				uintptr(unsafe.Pointer(&imageSize)),
			)
			if queryOK == 0 {
				_ = windows.CloseHandle(process)
				return errors.New("cannot verify running Local Core executable path")
			}
			image, pathErr := filepath.Abs(syscall.UTF16ToString(imageBuffer[:imageSize]))
			if pathErr != nil {
				_ = windows.CloseHandle(process)
				return errors.New("cannot normalize running Local Core executable path")
			}
			if strings.EqualFold(filepath.Clean(image), filepath.Clean(expected)) {
				var token windows.Token
				if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
					_ = windows.CloseHandle(process)
					return errors.New("cannot authenticate Local Core process owner")
				}
				owner, ownerErr := token.GetTokenUser()
				_ = token.Close()
				if ownerErr != nil || owner == nil || owner.User.Sid == nil ||
					!owner.User.Sid.Equals(currentUser.User.Sid) {
					_ = windows.CloseHandle(process)
					return errors.New("Local Core is running under another user; close it before updating")
				}
				if err := windows.TerminateProcess(process, 0); err != nil {
					_ = windows.CloseHandle(process)
					return errors.New("could not stop Local Core safely")
				}
				wait, waitErr := windows.WaitForSingleObject(process, 5000)
				_ = windows.CloseHandle(process)
				if waitErr != nil || wait != windows.WAIT_OBJECT_0 {
					return errors.New("Local Core did not exit before update")
				}
			} else {
				_ = windows.CloseHandle(process)
			}
		}
		entry = processEntry32Core{Size: uint32(unsafe.Sizeof(processEntry32Core{}))}
		ok, _, _ = process32NextCore.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	}
	return nil
}

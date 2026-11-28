//go:build windows

package scmbroker

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pipePath = `\.pipeWeDecent.SCM.v1`
const (
	pipeAccessDuplex = 0x00000003
	fileFlagFirstPipeInstance = 0x00080000
	pipeTypeByte = 0
	pipeReadModeByte = 0
	pipeWait = 0
	pipeRejectRemoteClients = 0x00000008
	tokenElevation = 20
	tokenIntegrityLevel = 25
	tokenUser = 1
	tokenGroups = 2
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	procCreateNamedPipe = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe = kernel32.NewProc("DisconnectNamedPipe")
	procGetNamedPipeClientPID = kernel32.NewProc("GetNamedPipeClientProcessId")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
	procRevertToSelf = advapi32.NewProc("RevertToSelf")
	procOpenThreadToken = advapi32.NewProc("OpenThreadToken")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
)

type tokenElevationInfo struct { TokenIsElevated uint32 }

func Run() error {
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil { return err }
	sec := &windows.SecurityAttributes{Length:uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor:sd}
	name, _ := windows.UTF16PtrFromString(pipePath)
	for {
		h, _, callErr := procCreateNamedPipe.Call(
			uintptr(unsafe.Pointer(name)),
			pipeAccessDuplex|fileFlagFirstPipeInstance,
			pipeTypeByte|pipeReadModeByte|pipeWait|pipeRejectRemoteClients,
			1, MaxResponseBytes, MaxRequestBytes, 0,
			uintptr(unsafe.Pointer(sec)),
		)
		if h == uintptr(windows.InvalidHandle) { return fmt.Errorf("create SCM broker pipe: %w", callErr) }
		if err := servePipe(windows.Handle(h)); err != nil {
			_ = windows.CloseHandle(windows.Handle(h))
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) { continue }
			return err
		}
		_ = windows.CloseHandle(windows.Handle(h))
	}
}

func servePipe(pipe windows.Handle) error {
	ok, _, callErr := procConnectNamedPipe.Call(uintptr(pipe), 0)
	if ok == 0 && !errors.Is(callErr, windows.ERROR_PIPE_CONNECTED) { return fmt.Errorf("connect broker pipe: %w", callErr) }
	pid, _, callErr := procGetNamedPipeClientPID.Call(uintptr(pipe), uintptr(unsafe.Pointer(new(uint32))))
	if pid == 0 { return fmt.Errorf("get pipe client PID: %w", callErr) }
	authorized, err := authenticateClient()
	if err != nil || !authorized { return errors.New("SCM broker: caller authentication rejected") }
	_ = procDisconnectNamedPipe
	return errors.New("SCM broker: authenticated IPC dispatch not enabled")
}

func authenticateClient() (authorized bool, err error) {
	r1, _, callErr := procImpersonateNamedPipeClient.Call(0)
	if r1 == 0 { return false, fmt.Errorf("impersonate pipe client: %w", callErr) }
	defer func() {
		r, _, e := procRevertToSelf.Call()
		if r == 0 { authorized = false; err = fmt.Errorf("revert impersonation: %w", e) }
	}()
	var token windows.Token
	r1, _, callErr = procOpenThreadToken.Call(uintptr(windows.CurrentThread()), uintptr(windows.TOKEN_QUERY), 1, uintptr(unsafe.Pointer(&token)))
	if r1 == 0 { return false, fmt.Errorf("open impersonation token: %w", callErr) }
	defer token.Close()
	var elevation tokenElevationInfo
	var returned uint32
	r1, _, callErr = procGetTokenInformation.Call(uintptr(token), tokenElevation, uintptr(unsafe.Pointer(&elevation)), unsafe.Sizeof(elevation), uintptr(unsafe.Pointer(&returned)))
	if r1 == 0 { return false, fmt.Errorf("query token elevation: %w", callErr) }
	if elevation.TokenIsElevated != 1 { return false, nil }
	// Publisher and product-image verification is a mandatory fail-closed gate before dispatch.
	return false, nil
}

var _ = os.ErrNotExist

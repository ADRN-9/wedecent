//go:build windows

package scmbroker

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pipePath                = `\\.\pipe\WeDecent.SCM.v1`
	pipeAccessDuplex        = 0x00000003
	fileFlagFirstPipe       = 0x00080000
	pipeTypeByte            = 0
	pipeReadModeByte        = 0
	pipeWait                = 0
	pipeRejectRemoteClients = 0x00000008
	tokenElevation          = 20
	tokenUser               = 1
)

var (
	kernel32                        = syscall.NewLazyDLL("kernel32.dll")
	procCreateNamedPipe             = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe            = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe         = kernel32.NewProc("DisconnectNamedPipe")
	procGetNamedPipeClientProcessID = kernel32.NewProc("GetNamedPipeClientProcessId")
	advapi32                        = syscall.NewLazyDLL("advapi32.dll")
	procImpersonateNamedPipeClient  = advapi32.NewProc("ImpersonateNamedPipeClient")
	procRevertToSelf                = advapi32.NewProc("RevertToSelf")
	procOpenThreadToken             = advapi32.NewProc("OpenThreadToken")
	procGetTokenInformation         = advapi32.NewProc("GetTokenInformation")
	procEqualSid                    = advapi32.NewProc("EqualSid")
)

type tokenElevationInfo struct {
	TokenIsElevated uint32
}

// Run owns the broker pipe. It deliberately dispatches no requests until
// publisher and complete token authorization have been independently reviewed.
func Run() error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return fmt.Errorf("construct broker pipe DACL: %w", err)
	}
	security := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	name, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return fmt.Errorf("encode broker pipe path: %w", err)
	}

	for {
		handle, _, callErr := procCreateNamedPipe.Call(
			uintptr(unsafe.Pointer(name)),
			pipeAccessDuplex|fileFlagFirstPipe,
			pipeTypeByte|pipeReadModeByte|pipeWait|pipeRejectRemoteClients,
			1,
			MaxResponseBytes,
			MaxRequestBytes,
			0,
			uintptr(unsafe.Pointer(security)),
		)
		if handle == uintptr(windows.InvalidHandle) {
			return fmt.Errorf("create SCM broker pipe: %w", callErr)
		}

		err := servePipe(windows.Handle(handle))
		_ = windows.CloseHandle(windows.Handle(handle))
		if err != nil {
			// A rejected client must not terminate the privileged broker.
			// Only a pipe/server infrastructure error stops the service.
			return err
		}
	}
}

func servePipe(pipe windows.Handle) error {
	connected, _, callErr := procConnectNamedPipe.Call(uintptr(pipe), 0)
	if connected == 0 && !errors.Is(callErr, windows.ERROR_PIPE_CONNECTED) {
		return fmt.Errorf("connect broker pipe: %w", callErr)
	}

	var pid uint32
	ok, _, callErr := procGetNamedPipeClientProcessID.Call(
		uintptr(pipe),
		uintptr(unsafe.Pointer(&pid)),
	)
	if ok == 0 || pid == 0 {
		_, _, _ = procDisconnectNamedPipe.Call(uintptr(pipe))
		return fmt.Errorf("get pipe client process ID: %w", callErr)
	}

	authorized, err := authenticateClient(pipe, pid)
	if err != nil || !authorized {
		_, _, _ = procDisconnectNamedPipe.Call(uintptr(pipe))
		// Fail closed without letting an unauthorized connection stop the service.
		return nil
	}

	_, _, _ = procDisconnectNamedPipe.Call(uintptr(pipe))
	// No IPC operation is dispatched in this foundation.
	return nil
}

func authenticateClient(pipe windows.Handle, pid uint32) (authorized bool, err error) {
	result, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if result == 0 {
		return false, fmt.Errorf("impersonate pipe client: %w", callErr)
	}

	defer func() {
		result, _, revertErr := procRevertToSelf.Call()
		if result == 0 {
			authorized = false
			err = fmt.Errorf("revert impersonation: %w", revertErr)
		}
	}()

	var clientToken windows.Token
	result, _, callErr = procOpenThreadToken.Call(
		uintptr(windows.GetCurrentThread()),
		uintptr(windows.TOKEN_QUERY),
		1,
		uintptr(unsafe.Pointer(&clientToken)),
	)
	if result == 0 {
		return false, fmt.Errorf("open impersonation token: %w", callErr)
	}
	defer clientToken.Close()

	var elevation tokenElevationInfo
	var returned uint32
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(clientToken),
		tokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&returned)),
	)
	if result == 0 {
		return false, fmt.Errorf("query token elevation: %w", callErr)
	}
	if elevation.TokenIsElevated != 1 {
		return false, nil
	}

	// Bind the impersonation token to the kernel-reported client process.
	// Publisher verification is still a mandatory, unimplemented authorization
	// gate, so this function intentionally never returns authorized=true.
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, fmt.Errorf("open pipe client process: %w", err)
	}
	defer windows.CloseHandle(process)

	var processToken windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &processToken); err != nil {
		return false, fmt.Errorf("open client process token: %w", err)
	}
	defer processToken.Close()

	var clientUserInfo, processUserInfo [1024]byte
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(clientToken),
		tokenUser,
		uintptr(unsafe.Pointer(&clientUserInfo[0])),
		uintptr(len(clientUserInfo)),
		uintptr(unsafe.Pointer(&returned)),
	)
	if result == 0 {
		return false, fmt.Errorf("query impersonated user: %w", callErr)
	}
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(processToken),
		tokenUser,
		uintptr(unsafe.Pointer(&processUserInfo[0])),
		uintptr(len(processUserInfo)),
		uintptr(unsafe.Pointer(&returned)),
	)
	if result == 0 {
		return false, fmt.Errorf("query process user: %w", callErr)
	}
	if !sameTokenUserSID(&clientUserInfo[0], &processUserInfo[0]) {
		return false, errors.New("pipe token does not match client process token")
	}

	return false, nil
}

// sameTokenUserSID compares the SID pointers in TOKEN_USER records.
func sameTokenUserSID(a, b *byte) bool {
	type sidAndAttributes struct {
		SID        uintptr
		Attributes uint32
	}
	x := (*sidAndAttributes)(unsafe.Pointer(a))
	y := (*sidAndAttributes)(unsafe.Pointer(b))
	if x.SID == 0 || y.SID == 0 {
		return false
	}
	result, _, _ := procEqualSid.Call(x.SID, y.SID)
	return result != 0
}

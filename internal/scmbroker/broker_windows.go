//go:build windows

package scmbroker

import (
	"errors"
	"fmt"
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
	var pid uint32
	ok, _, callErr = procGetNamedPipeClientPID.Call(uintptr(pipe), uintptr(unsafe.Pointer(&pid)))
	if ok == 0 || pid == 0 { return fmt.Errorf("get pipe client PID: %w", callErr) }
	authorized, err := authenticateClient(pipe, pid)
	if err != nil || !authorized { return errors.New("SCM broker: caller authentication rejected") }
	_ = procDisconnectNamedPipe.Call(uintptr(pipe))
	return errors.New("SCM broker: authenticated IPC dispatch not enabled")
}

func authenticateClient(pipe windows.Handle, pid uint32) (authorized bool, err error) {
	r1, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if r1 == 0 { return false, fmt.Errorf("impersonate pipe client: %w", callErr) }
	defer func() {
		r, _, e := procRevertToSelf.Call()
		if r == 0 { authorized = false; err = fmt.Errorf("revert impersonation: %w", e) }
	}()
	var token windows.Token
	r1, _, callErr = procOpenThreadToken.Call(uintptr(syscall.GetCurrentThread()), uintptr(windows.TOKEN_QUERY), 1, uintptr(unsafe.Pointer(&token)))
	if r1 == 0 { return false, fmt.Errorf("open impersonation token: %w", callErr) }
	defer token.Close()
	var elevation tokenElevationInfo
	var returned uint32
	r1, _, callErr = procGetTokenInformation.Call(uintptr(token), tokenElevation, uintptr(unsafe.Pointer(&elevation)), unsafe.Sizeof(elevation), uintptr(unsafe.Pointer(&returned)))
	if r1 == 0 { return false, fmt.Errorf("query token elevation: %w", callErr) }
	if elevation.TokenIsElevated != 1 { return false, nil }
	// Bind the pipe token to the process reported by the kernel. Image publisher
	// verification is intentionally a hard gate: no operation is dispatched until
	// the release process pins the approved installer signer certificate.
	var processToken windows.Token
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil { return false, fmt.Errorf("open pipe client process: %w", e) }
	defer windows.CloseHandle(process)
	if e = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &processToken); e != nil { return false, fmt.Errorf("open client process token: %w", e) }
	defer processToken.Close()
	var userInfo, processUserInfo [1024]byte
	var n uint32
	r1, _, callErr = procGetTokenInformation.Call(uintptr(token), tokenUser, uintptr(unsafe.Pointer(&userInfo[0])), uintptr(len(userInfo)), uintptr(unsafe.Pointer(&n)))
	if r1 == 0 { return false, fmt.Errorf("query impersonated user: %w", callErr) }
	r1, _, callErr = procGetTokenInformation.Call(uintptr(processToken), tokenUser, uintptr(unsafe.Pointer(&processUserInfo[0])), uintptr(len(processUserInfo)), uintptr(unsafe.Pointer(&n)))
	if r1 == 0 { return false, fmt.Errorf("query process user: %w", callErr) }
	if !sameTokenUserSID(&userInfo[0], &processUserInfo[0]) { return false, errors.New("pipe token does not match client process token") }
	return false, nil
}


// sameTokenUserSID compares the SID pointers returned in TOKEN_USER records.
func sameTokenUserSID(a, b *byte) bool {
	type sidAndAttributes struct { SID uintptr; Attributes uint32 }
	x := (*sidAndAttributes)(unsafe.Pointer(a))
	y := (*sidAndAttributes)(unsafe.Pointer(b))
	if x.SID == 0 || y.SID == 0 { return false }
	r, _, _ := advapi32.NewProc("EqualSid").Call(x.SID, y.SID)
	return r != 0
}

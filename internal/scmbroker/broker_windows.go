//go:build windows

package scmbroker

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"context"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pipePath                = `\\.\pipe\WeDecent.SCM.v1`
	pipeAccessDuplex        = 0x00000003
	fileFlagFirstPipe       = 0x00080000
	pipeTypeByte            = 0
	pipeReadModeByte        = 0
	pipeWait                = 1 // PIPE_NOWAIT; used with bounded cancellation polling.
	pipeRejectRemoteClients = 0x00000008
	tokenElevation          = 20
	tokenElevationType      = 18
	tokenIntegrityLevel     = 25
	tokenIsAppContainer     = 29
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
	procCheckTokenMembership        = advapi32.NewProc("CheckTokenMembership")
	procGetSidSubAuthorityCount    = advapi32.NewProc("GetSidSubAuthorityCount")
	procGetSidSubAuthority        = advapi32.NewProc("GetSidSubAuthority")
)

type tokenElevationInfo struct {
	TokenIsElevated uint32
}

// Run owns the broker pipe. It deliberately dispatches no requests until
// publisher and complete token authorization have been independently reviewed.
func Run() error {
	return RunContext(context.Background())
}

// RunContext serves only the authenticated, read-only broker foundation.
// Cancellation stops accepting new connections; no request dispatch is enabled.
func RunContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("SCM broker: nil context")
	}
	serviceSID, err := brokerServiceSID("WeDecentSCMBroker")
	if err != nil {
		return err
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + serviceSID + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
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

		pipe := windows.Handle(handle)
		err := connectPipe(ctx, pipe)
		if err == nil && ctx.Err() == nil {
			err = servePipe(pipe)
		}
		_ = windows.CloseHandle(pipe)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func connectPipe(ctx context.Context, pipe windows.Handle) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		connected, _, callErr := procConnectNamedPipe.Call(uintptr(pipe), 0)
		if connected != 0 || errors.Is(callErr, windows.ERROR_PIPE_CONNECTED) {
			return nil
		}
		if !errors.Is(callErr, syscall.Errno(535)) { // ERROR_PIPE_LISTENING
			return fmt.Errorf("connect broker pipe: %w", callErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func servePipe(pipe windows.Handle) error {

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

func authenticateClient(pipe windows.Handle, pid uint32) (bool, error) {
	return withImpersonation(
		func() error {
			result, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe))
			if result == 0 {
				return fmt.Errorf("impersonate pipe client: %w", callErr)
			}
			return nil
		},
		func() error {
			result, _, callErr := procRevertToSelf.Call()
			if result == 0 {
				return fmt.Errorf("revert impersonation: %w", callErr)
			}
			return nil
		},
		func() (bool, error) {
			var clientToken windows.Token
			result, _, callErr := procOpenThreadToken.Call(
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
			if err := validateAdministratorHighIntegrityToken(clientToken); err != nil {
				return false, err
			}

			// Bind the impersonation token to the kernel-reported client process.
			// Exact publisher verification remains a mandatory, unimplemented gate.
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

			// Until exact publisher policy is provisioned and verified, deny all callers.
			return false, nil
		},
	)
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


// validateAdministratorHighIntegrityToken checks the effective impersonation
// token, not the broker process token. It does not by itself authorize a client;
// exact publisher verification remains a separate mandatory gate.
func validateAdministratorHighIntegrityToken(token windows.Token) error {
	adminSID, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return fmt.Errorf("construct administrators SID: %w", err)
	}
	var isMember int32
	result, _, callErr := procCheckTokenMembership.Call(
		uintptr(token),
		uintptr(unsafe.Pointer(adminSID)),
		uintptr(unsafe.Pointer(&isMember)),
	)
	if result == 0 {
		return fmt.Errorf("check administrators membership: %w", callErr)
	}
	if isMember == 0 {
		return errors.New("client token is not an enabled administrator")
	}

	var elevationType uint32
	var returned uint32
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token),
		tokenElevationType,
		uintptr(unsafe.Pointer(&elevationType)),
		unsafe.Sizeof(elevationType),
		uintptr(unsafe.Pointer(&returned)),
	)
	if result == 0 {
		return fmt.Errorf("query token elevation type: %w", callErr)
	}
	if elevationType != 2 { // TokenElevationTypeFull
		return errors.New("client token is not fully elevated")
	}

	var appContainer uint32
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token),
		tokenIsAppContainer,
		uintptr(unsafe.Pointer(&appContainer)),
		unsafe.Sizeof(appContainer),
		uintptr(unsafe.Pointer(&returned)),
	)
	if result == 0 {
		return fmt.Errorf("query AppContainer token state: %w", callErr)
	}
	if appContainer != 0 {
		return errors.New("AppContainer clients are not authorized")
	}

	var integrity [256]byte
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token),
		tokenIntegrityLevel,
		uintptr(unsafe.Pointer(&integrity[0])),
		uintptr(len(integrity)),
		uintptr(unsafe.Pointer(&returned)),
	)
	if result == 0 {
		return fmt.Errorf("query token integrity level: %w", callErr)
	}
	type sidAndAttributes struct {
		SID        uintptr
		Attributes uint32
	}
	label := (*sidAndAttributes)(unsafe.Pointer(&integrity[0]))
	if label.SID == 0 {
		return errors.New("client token has no integrity SID")
	}
	count, _, _ := procGetSidSubAuthorityCount.Call(label.SID)
	if count == 0 || *(*byte)(unsafe.Pointer(count)) == 0 {
		return errors.New("client token integrity SID is malformed")
	}
	rid, _, _ := procGetSidSubAuthority.Call(label.SID, uintptr(*(*byte)(unsafe.Pointer(count))-1))
	if rid == 0 || *(*uint32)(unsafe.Pointer(rid)) < 0x3000 { // SECURITY_MANDATORY_HIGH_RID
		return errors.New("client token integrity is below High")
	}
	return nil
}


// brokerServiceSID derives the Windows service SID for the fixed broker service
// name. Installation must enable SERVICE_SID_TYPE_UNRESTRICTED (or a reviewed
// restricted equivalent) so the service token actually contains this SID.
func brokerServiceSID(serviceName string) (string, error) {
	if serviceName != "WeDecentSCMBroker" {
		return "", errors.New("SCM broker: unexpected service name")
	}
	units := utf16.Encode([]rune(strings.ToUpper(serviceName)))
	input := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(input[i*2:], unit)
	}
	digest := sha1.Sum(input)
	var sid strings.Builder
	sid.WriteString("S-1-5-80")
	for i := 0; i < 5; i++ {
		value := binary.LittleEndian.Uint32(digest[i*4 : i*4+4])
		fmt.Fprintf(&sid, "-%d", value)
	}
	return sid.String(), nil
}

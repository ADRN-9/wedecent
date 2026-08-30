//go:build windows

package winservice

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
)

const (
	serviceWin32OwnProcess   = 0x00000010
	serviceAutoStart         = 0x00000002
	serviceDemandStart       = 0x00000003
	serviceErrorNormal       = 0x00000001
	serviceConfigDescription = 0x00000001

	serviceStopped      = 0x00000001
	serviceStartPending = 0x00000002
	serviceStopPending  = 0x00000003
	serviceRunning      = 0x00000004

	serviceControlStop        = 0x00000001
	serviceControlInterrogate = 0x00000004
	serviceControlShutdown    = 0x00000005

	serviceAcceptStop     = 0x00000001
	serviceAcceptShutdown = 0x00000004

	scManagerAllAccess  = 0x000F003F
	serviceAllAccess    = 0x000F01FF
	scStatusProcessInfo = 0
)

var (
	advapi32                          = syscall.NewLazyDLL("advapi32.dll")
	procOpenSCManagerW                = advapi32.NewProc("OpenSCManagerW")
	procCreateServiceW                = advapi32.NewProc("CreateServiceW")
	procOpenServiceW                  = advapi32.NewProc("OpenServiceW")
	procDeleteService                 = advapi32.NewProc("DeleteService")
	procCloseServiceHandle            = advapi32.NewProc("CloseServiceHandle")
	procStartServiceW                 = advapi32.NewProc("StartServiceW")
	procControlService                = advapi32.NewProc("ControlService")
	procQueryServiceStatusEx          = advapi32.NewProc("QueryServiceStatusEx")
	procStartServiceCtrlDispatcherW   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32.NewProc("SetServiceStatus")
	procChangeServiceConfig2W         = advapi32.NewProc("ChangeServiceConfig2W")
)

type InstallOptions struct {
	Name        string
	DisplayName string
	Description string
	Account     string
	Password    string
	Executable  string
	Arguments   []string
	Automatic   bool
}

type Status struct {
	State     string
	ProcessID uint32
	ExitCode  uint32
}

type serviceDescription struct {
	Description *uint16
}

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type serviceStatusProcess struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessID               uint32
	ServiceFlags            uint32
}

type serviceTableEntry struct {
	Name *uint16
	Proc uintptr
}

func Install(opts InstallOptions) error {
	if strings.TrimSpace(opts.Name) == "" {
		return errors.New("service name is required")
	}
	if strings.TrimSpace(opts.Account) == "" {
		return errors.New("service account is required")
	}
	if opts.Executable == "" {
		return errors.New("service executable is required")
	}
	exe, err := filepath.Abs(opts.Executable)
	if err != nil {
		return fmt.Errorf("resolve service executable: %w", err)
	}
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("service executable: %w", err)
	}

	manager, err := openManager()
	if err != nil {
		return err
	}
	defer closeServiceHandle(manager)

	name, err := syscall.UTF16PtrFromString(opts.Name)
	if err != nil {
		return err
	}
	display := opts.DisplayName
	if display == "" {
		display = opts.Name
	}
	displayPtr, err := syscall.UTF16PtrFromString(display)
	if err != nil {
		return err
	}
	commandLine := syscall.EscapeArg(exe)
	for _, arg := range opts.Arguments {
		commandLine += " " + syscall.EscapeArg(arg)
	}
	commandPtr, err := syscall.UTF16PtrFromString(commandLine)
	if err != nil {
		return err
	}
	accountPtr, err := syscall.UTF16PtrFromString(opts.Account)
	if err != nil {
		return err
	}
	var passwordPtr *uint16
	if opts.Password != "" {
		passwordPtr, err = syscall.UTF16PtrFromString(opts.Password)
		if err != nil {
			return err
		}
	}
	startType := uintptr(serviceDemandStart)
	if opts.Automatic {
		startType = serviceAutoStart
	}

	h, _, callErr := procCreateServiceW.Call(
		manager,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(displayPtr)),
		serviceAllAccess,
		serviceWin32OwnProcess,
		startType,
		serviceErrorNormal,
		uintptr(unsafe.Pointer(commandPtr)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(accountPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
	)
	if h == 0 {
		return winCallError("CreateServiceW", callErr)
	}
	defer closeServiceHandle(h)
	if strings.TrimSpace(opts.Description) != "" {
		descPtr, err := syscall.UTF16PtrFromString(opts.Description)
		if err != nil {
			_, _, _ = procDeleteService.Call(h)
			return err
		}
		desc := serviceDescription{Description: descPtr}
		r1, _, callErr := procChangeServiceConfig2W.Call(h, serviceConfigDescription, uintptr(unsafe.Pointer(&desc)))
		if r1 == 0 {
			_, _, _ = procDeleteService.Call(h)
			return winCallError("ChangeServiceConfig2W(description)", callErr)
		}
	}
	return nil
}

func Start(name string) error {
	h, err := openService(name)
	if err != nil {
		return err
	}
	defer closeServiceHandle(h)
	r1, _, callErr := procStartServiceW.Call(h, 0, 0)
	if r1 == 0 {
		return winCallError("StartServiceW", callErr)
	}
	return waitForState(h, serviceRunning, 30*time.Second)
}

func Stop(name string) error {
	h, err := openService(name)
	if err != nil {
		return err
	}
	defer closeServiceHandle(h)
	st, err := queryStatusHandle(h)
	if err != nil {
		return err
	}
	if st.CurrentState == serviceStopped {
		return nil
	}
	var basic serviceStatus
	r1, _, callErr := procControlService.Call(h, serviceControlStop, uintptr(unsafe.Pointer(&basic)))
	if r1 == 0 {
		return winCallError("ControlService(STOP)", callErr)
	}
	return waitForState(h, serviceStopped, 30*time.Second)
}

func Uninstall(name string) error {
	h, err := openService(name)
	if err != nil {
		return err
	}
	defer closeServiceHandle(h)
	st, qerr := queryStatusHandle(h)
	if qerr == nil && st.CurrentState != serviceStopped {
		var basic serviceStatus
		_, _, _ = procControlService.Call(h, serviceControlStop, uintptr(unsafe.Pointer(&basic)))
		_ = waitForState(h, serviceStopped, 20*time.Second)
	}
	r1, _, callErr := procDeleteService.Call(h)
	if r1 == 0 {
		return winCallError("DeleteService", callErr)
	}
	return nil
}

func Query(name string) (Status, error) {
	h, err := openService(name)
	if err != nil {
		return Status{}, err
	}
	defer closeServiceHandle(h)
	st, err := queryStatusHandle(h)
	if err != nil {
		return Status{}, err
	}
	return Status{State: stateName(st.CurrentState), ProcessID: st.ProcessID, ExitCode: st.Win32ExitCode}, nil
}

func openManager() (uintptr, error) {
	h, _, callErr := procOpenSCManagerW.Call(0, 0, scManagerAllAccess)
	if h == 0 {
		return 0, winCallError("OpenSCManagerW", callErr)
	}
	return h, nil
}

func openService(name string) (uintptr, error) {
	manager, err := openManager()
	if err != nil {
		return 0, err
	}
	defer closeServiceHandle(manager)
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, _, callErr := procOpenServiceW.Call(manager, uintptr(unsafe.Pointer(namePtr)), serviceAllAccess)
	if h == 0 {
		return 0, winCallError("OpenServiceW", callErr)
	}
	return h, nil
}

func closeServiceHandle(h uintptr) {
	if h != 0 {
		_, _, _ = procCloseServiceHandle.Call(h)
	}
}

func queryStatusHandle(h uintptr) (serviceStatusProcess, error) {
	var st serviceStatusProcess
	var needed uint32
	r1, _, callErr := procQueryServiceStatusEx.Call(
		h,
		scStatusProcessInfo,
		uintptr(unsafe.Pointer(&st)),
		unsafe.Sizeof(st),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		return serviceStatusProcess{}, winCallError("QueryServiceStatusEx", callErr)
	}
	return st, nil
}

func waitForState(h uintptr, want uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := queryStatusHandle(h)
		if err != nil {
			return err
		}
		if st.CurrentState == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service did not reach %s before timeout (current %s)", stateName(want), stateName(st.CurrentState))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func stateName(state uint32) string {
	switch state {
	case serviceStopped:
		return "stopped"
	case serviceStartPending:
		return "start-pending"
	case serviceStopPending:
		return "stop-pending"
	case serviceRunning:
		return "running"
	default:
		return fmt.Sprintf("state-%d", state)
	}
}

func winCallError(op string, err error) error {
	if err == nil || errors.Is(err, syscall.Errno(0)) {
		return fmt.Errorf("%s failed", op)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// Run connects the current process to the Windows Service Control Manager and
// runs execute until the SCM requests stop or shutdown.
func Run(name string, execute func(context.Context) error) error {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r := &serviceRunner{name: name, namePtr: namePtr, execute: execute, done: make(chan struct{})}
	serviceRunMu.Lock()
	if activeRunner != nil {
		serviceRunMu.Unlock()
		return errors.New("a Windows service is already active in this process")
	}
	activeRunner = r
	serviceRunMu.Unlock()
	defer func() {
		serviceRunMu.Lock()
		activeRunner = nil
		serviceRunMu.Unlock()
	}()

	table := [2]serviceTableEntry{
		{Name: namePtr, Proc: serviceMainCallback},
		{},
	}
	r1, _, callErr := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r1 == 0 {
		return winCallError("StartServiceCtrlDispatcherW", callErr)
	}
	<-r.done
	return r.err
}

type serviceRunner struct {
	mu           sync.Mutex
	name         string
	namePtr      *uint16
	execute      func(context.Context) error
	statusHandle uintptr
	status       serviceStatus
	cancel       context.CancelFunc
	err          error
	done         chan struct{}
}

var (
	serviceRunMu        sync.Mutex
	activeRunner        *serviceRunner
	serviceMainCallback = syscall.NewCallback(serviceMain)
	serviceCtrlCallback = syscall.NewCallback(serviceControlHandler)
)

func serviceMain(_, _ uintptr) uintptr {
	serviceRunMu.Lock()
	r := activeRunner
	serviceRunMu.Unlock()
	if r == nil {
		return 0
	}
	h, _, callErr := procRegisterServiceCtrlHandlerExW.Call(
		uintptr(unsafe.Pointer(r.namePtr)),
		serviceCtrlCallback,
		0,
	)
	if h == 0 {
		r.finish(winCallError("RegisterServiceCtrlHandlerExW", callErr))
		return 0
	}
	r.mu.Lock()
	r.statusHandle = h
	r.mu.Unlock()
	r.setStatus(serviceStartPending, 0, 10_000)

	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cancel = cancel
	r.mu.Unlock()
	r.setStatus(serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0)
	err := r.execute(ctx)
	cancel()
	r.setStatus(serviceStopped, 0, 0)
	r.finish(err)
	return 0
}

func serviceControlHandler(control, _, _, _ uintptr) uintptr {
	serviceRunMu.Lock()
	r := activeRunner
	serviceRunMu.Unlock()
	if r == nil {
		return 0
	}
	switch uint32(control) {
	case serviceControlStop, serviceControlShutdown:
		r.setStatus(serviceStopPending, 0, 10_000)
		r.mu.Lock()
		cancel := r.cancel
		r.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	case serviceControlInterrogate:
		r.mu.Lock()
		st := r.status
		h := r.statusHandle
		r.mu.Unlock()
		if h != 0 {
			_, _, _ = procSetServiceStatus.Call(h, uintptr(unsafe.Pointer(&st)))
		}
	}
	return 0
}

func (r *serviceRunner) setStatus(state, accepts, waitHint uint32) {
	r.mu.Lock()
	if state == serviceStartPending || state == serviceStopPending {
		r.status.CheckPoint++
	} else {
		r.status.CheckPoint = 0
	}
	r.status.ServiceType = serviceWin32OwnProcess
	r.status.CurrentState = state
	r.status.ControlsAccepted = accepts
	r.status.WaitHint = waitHint
	st := r.status
	h := r.statusHandle
	r.mu.Unlock()
	if h != 0 {
		_, _, _ = procSetServiceStatus.Call(h, uintptr(unsafe.Pointer(&st)))
	}
}

func (r *serviceRunner) finish(err error) {
	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
	select {
	case <-r.done:
	default:
		close(r.done)
	}
}

func qualifyAccountForLookup(account, computerName string) string {
	account = strings.TrimSpace(account)
	if strings.HasPrefix(account, `.\`) {
		return computerName + `\` + strings.TrimPrefix(account, `.\`)
	}
	return account
}

func accountSIDPrincipal(account string) (string, error) {
	account = strings.TrimSpace(account)
	lookupAccount := account
	if strings.HasPrefix(account, `.\`) {
		computerName, err := syscall.ComputerName()
		if err != nil {
			return "", fmt.Errorf("resolve computer name for service account %q: %w", account, err)
		}
		lookupAccount = qualifyAccountForLookup(account, computerName)
	}

	sid, _, _, err := syscall.LookupSID("", lookupAccount)
	if err != nil {
		return "", fmt.Errorf("resolve service account %q to SID: %w", account, err)
	}
	sidText, err := sid.String()
	if err != nil {
		return "", fmt.Errorf("format SID for service account %q: %w", account, err)
	}
	return "*" + sidText, nil
}

// RestrictDirectory removes inherited ACL entries and grants full control only
// to the configured service account, LocalSystem, and local Administrators.
// The caller must be elevated and the directory must already exist.
func RestrictDirectory(path, account string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("state directory is required")
	}
	if strings.TrimSpace(account) == "" {
		return errors.New("service account is required")
	}
	clean := filepath.Clean(path)
	principal, err := accountSIDPrincipal(account)
	if err != nil {
		return err
	}

	// Protect the state-directory root and make the allowed principals
	// inheritable. Do not apply /inheritance:r recursively: doing so removes
	// inherited ACEs from existing files before the new parent ACEs can
	// propagate to them.
	cmd := exec.Command(
		"icacls.exe",
		clean,
		"/inheritance:r",
		"/grant:r",
		principal+":(OI)(CI)F",
		"*S-1-5-18:(OI)(CI)F",
		"*S-1-5-32-544:(OI)(CI)F",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restrict state directory ACL: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Existing state files were created before ACL hardening. Re-enable
	// inheritance and reset their ACLs so they receive the root directory's
	// restricted inheritable ACEs. The wildcard intentionally excludes the
	// root itself from /reset.
	children := filepath.Join(clean, "*")
	for _, args := range [][]string{
		{children, "/inheritance:e", "/T", "/C"},
		{children, "/reset", "/T", "/C"},
	} {
		out, err := exec.Command("icacls.exe", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("propagate state directory ACL: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

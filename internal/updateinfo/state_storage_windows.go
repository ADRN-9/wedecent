//go:build windows

package updateinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var (
	kernel32UpdateState = syscall.NewLazyDLL("kernel32.dll")
	procMoveFileExW     = kernel32UpdateState.NewProc("MoveFileExW")
)

const (
	updateStateSystemSID = "S-1-5-18"
	updateStateAdminSID  = "S-1-5-32-544"
)

func validateStateFileInfo(path string, info os.FileInfo) error {
	return validateWindowsUpdateStatePath(path, info, false)
}

func validateStateDirInfo(path string, info os.FileInfo) error {
	return validateWindowsUpdateStatePath(path, info, true)
}

func validateWindowsUpdateStatePath(path string, before os.FileInfo, directory bool) error {
	if before.Mode()&os.ModeSymlink != 0 || (directory && !before.IsDir()) || (!directory && !before.Mode().IsRegular()) {
		return fmt.Errorf("%w: update state path has an unsafe file type", ErrInvalidState)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("%w: encode update state path: %v", ErrInvalidState, err)
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: update state path is unavailable or a reparse point", ErrInvalidState)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("%w: read update state owner and DACL: %v", ErrInvalidState, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: update state owner is unavailable", ErrInvalidState)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: update state requires a non-null DACL", ErrInvalidState)
	}

	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("%w: read update process SID: %v", ErrInvalidState, err)
	}
	adminSID, err := windows.StringToSid(updateStateAdminSID)
	if err != nil {
		return fmt.Errorf("%w: resolve Administrators SID: %v", ErrInvalidState, err)
	}
	isAdmin, err := token.IsMember(adminSID)
	if err != nil {
		return fmt.Errorf("%w: inspect updater administrator token: %v", ErrInvalidState, err)
	}

	currentSID := user.User.Sid.String()
	rootSID := owner.String()
	if !directory {
		parent := filepath.Dir(path)
		parentInfo, err := os.Lstat(parent)
		if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: update state parent is not a real directory", ErrInvalidState)
		}
		parentName, err := windows.UTF16PtrFromString(parent)
		if err != nil {
			return fmt.Errorf("%w: encode update state parent: %v", ErrInvalidState, err)
		}
		parentAttrs, err := windows.GetFileAttributes(parentName)
		if err != nil || parentAttrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("%w: update state parent is a reparse point", ErrInvalidState)
		}
		parentSD, err := windows.GetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil || parentSD == nil {
			return fmt.Errorf("%w: read update state parent owner: %v", ErrInvalidState, err)
		}
		parentOwner, _, err := parentSD.Owner()
		if err != nil || parentOwner == nil {
			return fmt.Errorf("%w: update state parent owner is unavailable", ErrInvalidState)
		}
		rootSID = parentOwner.String()
	}
	if err := validateUpdateStateOwner(owner.String(), currentSID, rootSID, isAdmin); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	if err := validateUpdateStateDACL(sd.String(), currentSID, rootSID, isAdmin); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return fmt.Errorf("%w: update state path changed during ACL verification", ErrInvalidState)
	}
	return nil
}

func validateUpdateStateOwner(ownerSID, currentSID, rootSID string, isAdmin bool) error {
	if ownerSID == "" || currentSID == "" || rootSID == "" {
		return errors.New("update state owner is unavailable")
	}
	if ownerSID == currentSID || ownerSID == updateStateSystemSID || ownerSID == updateStateAdminSID {
		return nil
	}
	if isAdmin && ownerSID == rootSID {
		return nil
	}
	return errors.New("update state owner is outside the active user/service boundary")
}

func validateUpdateStateDACL(sddl, currentSID, rootSID string, isAdmin bool) error {
	start := strings.Index(sddl, "D:")
	if start < 0 || currentSID == "" || rootSID == "" {
		return errors.New("Windows update state requires an explicit DACL")
	}
	entries := sddl[start+2:]
	if end := strings.Index(entries, "S:"); end >= 0 {
		entries = entries[:end]
	}
	if !strings.Contains(entries, "(") || strings.Count(entries, "(") != strings.Count(entries, ")") {
		return errors.New("Windows update state DACL is missing or malformed")
	}
	current, err := windows.StringToSid(currentSID)
	if err != nil || current == nil || !current.IsValid() {
		return errors.New("invalid updater process SID")
	}
	root, err := windows.StringToSid(rootSID)
	if err != nil || root == nil || !root.IsValid() {
		return errors.New("invalid update state root-owner SID")
	}
	system, err := windows.StringToSid(updateStateSystemSID)
	if err != nil {
		return fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	administrators, err := windows.StringToSid(updateStateAdminSID)
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}
	grantsCurrent, grantsRoot := false, false
	for {
		open := strings.IndexByte(entries, '(')
		if open < 0 {
			if strings.Trim(entries, "PAIR") != "" {
				return errors.New("unsupported update state DACL flags")
			}
			break
		}
		if strings.Trim(entries[:open], "PAIR") != "" {
			return errors.New("unsupported update state DACL prefix")
		}
		end := strings.IndexByte(entries[open+1:], ')')
		if end < 0 {
			return errors.New("unterminated update state ACE")
		}
		end += open + 1
		parts := strings.Split(entries[open+1:end], ";")
		if len(parts) != 6 || parts[5] == "" || parts[0] != "A" || parts[3] != "" || parts[4] != "" {
			return errors.New("unsupported update state ACE representation")
		}
		trustee, err := windows.StringToSid(parts[5])
		if err != nil || trustee == nil || !trustee.IsValid() {
			return errors.New("update state ACE trustee SID is invalid")
		}
		if !trustee.Equals(current) && !trustee.Equals(root) &&
			!trustee.Equals(system) && !trustee.Equals(administrators) {
			return fmt.Errorf("update state grants access to unauthorized SID %s", parts[5])
		}
		if parts[2] != "FA" && parts[2] != "GA" && parts[2] != "0x1f01ff" && parts[2] != "0x001f01ff" {
			return errors.New("update state ACE must grant full control")
		}
		if !strings.Contains(parts[1], "IO") {
			if trustee.Equals(current) || (isAdmin && trustee.Equals(administrators)) {
				grantsCurrent = true
			}
			if trustee.Equals(root) {
				grantsRoot = true
			}
		}
		entries = entries[end+1:]
	}
	if !grantsCurrent || !grantsRoot {
		return errors.New("update state DACL does not grant full control to active account and state owner")
	}
	return nil
}

func replaceStateFile(tmpPath, path, _ string) error {
	from, err := syscall.UTF16PtrFromString(tmpPath)
	if err != nil {
		return fmt.Errorf("%w: encode update state temp path: %v", ErrInvalidState, err)
	}
	to, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("%w: encode update state path: %v", ErrInvalidState, err)
	}
	r1, _, callErr := procMoveFileExW.Call(
		uintptr(unsafe.Pointer(from)),
		uintptr(unsafe.Pointer(to)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if r1 == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == 0 {
			return fmt.Errorf("%w: MoveFileExW failed", ErrInvalidState)
		}
		return fmt.Errorf("%w: MoveFileExW failed: %v", ErrInvalidState, callErr)
	}
	return nil
}

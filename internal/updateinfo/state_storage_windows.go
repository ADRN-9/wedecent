//go:build windows

package updateinfo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	updateStateSystemSID           = "S-1-5-18"
	updateStateAdminSID            = "S-1-5-32-544"
	updateStateTrustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
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
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%w: resolve update state path: %v", ErrInvalidState, err)
	}
	absolute = filepath.Clean(absolute)
	name, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return fmt.Errorf("%w: encode update state path: %v", ErrInvalidState, err)
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: update state path is unavailable or a reparse point", ErrInvalidState)
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
	rootSID, err := validateUpdateStateAncestorChain(absolute, currentSID, false)
	if err != nil {
		return err
	}

	sd, err := windows.GetNamedSecurityInfo(absolute, windows.SE_FILE_OBJECT,
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
	if err := validateUpdateStateOwner(owner.String(), currentSID, rootSID, isAdmin); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	if err := validateUpdateStateDACL(sd.String(), currentSID, rootSID, isAdmin); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	after, err := os.Lstat(absolute)
	if err != nil || !os.SameFile(before, after) {
		return fmt.Errorf("%w: update state path changed during ACL verification", ErrInvalidState)
	}
	return nil
}

// validateUpdateStateAncestorChain verifies every directory from the local
// volume root through the state path's parent. The final object is validated
// separately. UNC and device paths are rejected because their namespace and
// ACL semantics are outside this local updater-state trust boundary.
func validateStateDirAncestors(dir string) error {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("%w: resolve update state directory: %v", ErrInvalidState, err)
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("%w: read update process SID: %v", ErrInvalidState, err)
	}
	if _, err := validateUpdateStateAncestorChain(absolute, user.User.Sid.String(), true); err != nil {
		return err
	}
	return nil
}

func validateUpdateStateAncestorChain(path, currentSID string, allowMissing bool) (string, error) {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || path[2:3] != string(os.PathSeparator) {
		return "", fmt.Errorf("%w: update state must reside on a local drive path", ErrInvalidState)
	}
	parent := filepath.Dir(path)
	rest := strings.TrimLeft(strings.TrimPrefix(parent, volume), string(os.PathSeparator))
	components := []string{volume + string(os.PathSeparator)}
	current := components[0]
	if rest != "" {
		for _, part := range strings.Split(rest, string(os.PathSeparator)) {
			if part == "" || part == "." || part == ".." {
				return "", fmt.Errorf("%w: update state ancestor path is not canonical", ErrInvalidState)
			}
			current = filepath.Join(current, part)
			components = append(components, current)
		}
	}

	var parentOwner string
	type checkedAncestor struct {
		path string
		info os.FileInfo
	}
	checked := make([]checkedAncestor, 0, len(components))
	for _, component := range components {
		info, err := os.Lstat(component)
		if errors.Is(err, os.ErrNotExist) {
			if allowMissing {
				break
			}
			return "", fmt.Errorf("%w: update state ancestor is missing: %s", ErrInvalidState, component)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: update state ancestor is not a directory or is a reparse point: %s", ErrInvalidState, component)
		}
		name, err := windows.UTF16PtrFromString(component)
		if err != nil {
			return "", fmt.Errorf("%w: encode update state ancestor: %v", ErrInvalidState, err)
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return "", fmt.Errorf("%w: update state ancestor traverses a reparse point: %s", ErrInvalidState, component)
		}
		sd, err := windows.GetNamedSecurityInfo(component, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil || sd == nil {
			return "", fmt.Errorf("%w: read update state ancestor security: %s", ErrInvalidState, component)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil {
			return "", fmt.Errorf("%w: update state ancestor owner is unavailable: %s", ErrInvalidState, component)
		}
		dacl, _, err := sd.DACL()
		if err != nil || dacl == nil {
			return "", fmt.Errorf("%w: update state ancestor requires a non-null DACL: %s", ErrInvalidState, component)
		}
		ownerSID := owner.String()
		if err := validateUpdateStateAncestorOwner(ownerSID, currentSID); err != nil {
			return "", fmt.Errorf("%w: unsafe update state ancestor owner at %s: %v", ErrInvalidState, component, err)
		}
		if err := validateUpdateStateAncestorDACL(sd.String(), currentSID); err != nil {
			return "", fmt.Errorf("%w: unsafe update state ancestor ACL at %s: %v", ErrInvalidState, component, err)
		}
		parentOwner = ownerSID
		checked = append(checked, checkedAncestor{path: component, info: info})
	}
	for _, ancestor := range checked {
		after, err := os.Lstat(ancestor.path)
		if err != nil || !os.SameFile(ancestor.info, after) {
			return "", fmt.Errorf("%w: update state ancestor changed during ACL verification: %s", ErrInvalidState, ancestor.path)
		}
		name, err := windows.UTF16PtrFromString(ancestor.path)
		if err != nil {
			return "", fmt.Errorf("%w: encode update state ancestor: %v", ErrInvalidState, err)
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return "", fmt.Errorf("%w: update state ancestor became a reparse point: %s", ErrInvalidState, ancestor.path)
		}
	}
	return parentOwner, nil
}

func validateUpdateStateAncestorOwner(ownerSID, currentSID string) error {
	if ownerSID == currentSID || ownerSID == updateStateSystemSID ||
		ownerSID == updateStateAdminSID || ownerSID == updateStateTrustedInstallerSID {
		return nil
	}
	return errors.New("ancestor owner is not the active user, SYSTEM, Administrators, or TrustedInstaller")
}

func validateUpdateStateAncestorDACL(sddl, currentSID string) error {
	start := strings.Index(sddl, "D:")
	if start < 0 {
		return errors.New("ancestor has no explicit DACL")
	}
	entries := sddl[start+2:]
	if end := strings.Index(entries, "S:"); end >= 0 {
		entries = entries[:end]
	}
	open := strings.IndexByte(entries, '(')
	if open < 0 {
		return errors.New("ancestor DACL is empty or malformed")
	}
	for _, flag := range entries[:open] {
		if !strings.ContainsRune("PAIR", flag) {
			return errors.New("ancestor DACL has unsupported control flags")
		}
	}
	entries = entries[open:]
	trusted := map[string]bool{
		currentSID: true, updateStateSystemSID: true,
		updateStateAdminSID: true, updateStateTrustedInstallerSID: true,
	}
	// Ancestors must not be replaceable or have their security descriptor
	// changed by untrusted principals. Non-destructive create/write grants are
	// checked on the actual state directory and state file before state I/O.
	const dangerous = uint32(0x00000010 | 0x00000040 | 0x00000100 |
		0x00010000 | 0x00040000 | 0x00080000 | 0x10000000)
	for len(entries) > 0 {
		if entries[0] != '(' {
			return errors.New("ancestor DACL contains unsupported data")
		}
		end := strings.IndexByte(entries[1:], ')')
		if end < 0 {
			return errors.New("ancestor DACL contains an unterminated ACE")
		}
		end++
		parts := strings.Split(entries[1:end], ";")
		if len(parts) != 6 || parts[0] != "A" || parts[5] == "" || parts[3] != "" || parts[4] != "" {
			return errors.New("ancestor DACL contains an unsupported ACE")
		}
		mask, err := parseUpdateStateAccessMask(parts[2])
		if err != nil {
			return err
		}
		trustee, err := windows.StringToSid(parts[5])
		if err != nil || trustee == nil || !trustee.IsValid() {
			return errors.New("ancestor DACL contains an invalid trustee SID")
		}
		flags, err := parseUpdateStateACEFlags(parts[1])
		if err != nil {
			return err
		}
		// Inherited ACEs are checked again on each actual child object. An
		// inherit-only ACE does not grant rights on this directory; the final
		// state-object DACL rejects inherited write grants before state I/O.
		effectiveOnDirectory := flags&updateStateACEInheritOnly == 0
		isCreatorOwnerInheritance := trustee.String() == "S-1-3-0" &&
			flags&updateStateACEInheritOnly != 0 &&
			flags&(updateStateACEObjectInherit|updateStateACEContainerInherit) != 0
		if mask&dangerous != 0 && effectiveOnDirectory && !trusted[trustee.String()] && !isCreatorOwnerInheritance {
			return fmt.Errorf("untrusted SID %s has namespace-modifying rights 0x%08x (ACE flags %q)", trustee.String(), mask&dangerous, parts[1])
		}
		entries = entries[end+1:]
	}
	return nil
}

const (
	updateStateACEObjectInherit    = 1 << 0
	updateStateACEContainerInherit = 1 << 1
	updateStateACEInheritOnly      = 1 << 2
)

func parseUpdateStateACEFlags(value string) (uint8, error) {
	var flags uint8
	for len(value) > 0 {
		if len(value) < 2 {
			return 0, errors.New("ancestor DACL has malformed ACE flags")
		}
		switch value[:2] {
		case "OI":
			flags |= updateStateACEObjectInherit
		case "CI":
			flags |= updateStateACEContainerInherit
		case "IO":
			flags |= updateStateACEInheritOnly
		case "NP", "ID", "SA", "FA":
		default:
			return 0, errors.New("ancestor DACL has unsupported ACE flags")
		}
		value = value[2:]
	}
	return flags, nil
}

func parseUpdateStateAccessMask(value string) (uint32, error) {
	if strings.HasPrefix(value, "0x") {
		mask, err := strconv.ParseUint(value[2:], 16, 32)
		if err != nil {
			return 0, errors.New("ancestor DACL has an invalid numeric access mask")
		}
		return uint32(mask), nil
	}
	var mask uint32
	for len(value) > 0 {
		if len(value) < 2 {
			return 0, errors.New("ancestor DACL has an unknown access right")
		}
		token := value[:2]
		var right uint32
		switch token {
		case "FA":
			right = 0x001F01FF
		case "FR":
			right = 0x00020089
		case "FW":
			right = 0x00000116
		case "FX":
			right = 0x000200A0
		case "GA":
			right = 0x10000000
		case "GR":
			right = 0x80000000
		case "GW":
			right = 0x40000000
		case "GX":
			right = 0x20000000
		case "WD":
			right = 0x00040000
		case "WO":
			right = 0x00080000
		case "DC":
			right = 0x00000040
		case "DE", "SD":
			right = 0x00010000
		case "AD":
			right = 0x00000004
		case "LC":
			// On filesystem directories, mask 0x4 can add a child directory.
			right = 0x00000004
		case "RC":
			right = 0x00020000
		default:
			return 0, fmt.Errorf("ancestor DACL has unsupported access right %q", token)
		}
		mask |= right
		value = value[2:]
	}
	return mask, nil
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
	const dangerous = uint32(0x00000002 | 0x00000004 | 0x00000010 | 0x00000040 |
		0x00000100 | 0x00010000 | 0x00040000 | 0x00080000 |
		0x10000000 | 0x40000000)
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
		if len(parts) != 6 || parts[0] != "A" || parts[5] == "" || parts[3] != "" || parts[4] != "" {
			return errors.New("unsupported update state ACE representation")
		}
		trustee, err := windows.StringToSid(parts[5])
		if err != nil || trustee == nil || !trustee.IsValid() {
			return errors.New("update state ACE trustee SID is invalid")
		}
		flags, err := parseUpdateStateACEFlags(parts[1])
		if err != nil {
			return err
		}
		mask, err := parseUpdateStateAccessMask(parts[2])
		if err != nil {
			return err
		}
		trusted := trustee.Equals(current) || trustee.Equals(root) ||
			trustee.Equals(system) || trustee.Equals(administrators)
		if !trusted {
			if mask&dangerous != 0 {
				return fmt.Errorf("update state grants namespace or data modification rights to unauthorized SID %s", trustee.String())
			}
			entries = entries[end+1:]
			continue
		}
		if mask != 0x001F01FF && mask != 0x10000000 {
			return errors.New("trusted update state ACE must grant full control")
		}
		if flags&updateStateACEInheritOnly == 0 {
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

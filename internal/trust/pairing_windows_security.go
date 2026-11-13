//go:build windows

package trust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	windowsSystemSID = "S-1-5-18"
	windowsAdminSID  = "S-1-5-32-544"
)

// Pairing state may be owned by its dedicated service account, by the
// administrator provisioning that account, or by the current user. The
// ownership transition is trusted only when the actual DACL remains narrow.
func secureWindowsPairingPath(path string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return errors.New("pairing state is a symbolic link")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("pairing state is a Windows reparse point")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("read pairing ACL: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("read pairing owner: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("pairing state requires a non-null DACL")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("read pairing process SID: %v", err)
	}
	adminSID, err := windows.StringToSid(windowsAdminSID)
	if err != nil {
		return err
	}
	isAdmin, err := token.IsMember(adminSID)
	if err != nil {
		return fmt.Errorf("check pairing administrator token: %w", err)
	}
	currentSID := user.User.Sid.String()
	rootSID := owner.String()
	if !before.IsDir() {
		parent := filepath.Dir(path)
		parentInfo, err := os.Lstat(parent)
		if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("pairing parent is not a regular directory")
		}
		parentName, err := windows.UTF16PtrFromString(parent)
		if err != nil {
			return err
		}
		parentAttrs, err := windows.GetFileAttributes(parentName)
		if err != nil || parentAttrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("pairing parent is a reparse point")
		}
		parentSD, err := windows.GetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION)
		if err != nil || parentSD == nil {
			return fmt.Errorf("read pairing parent owner: %v", err)
		}
		parentOwner, _, err := parentSD.Owner()
		if err != nil || parentOwner == nil {
			return errors.New("pairing parent owner is unavailable")
		}
		rootSID = parentOwner.String()
	}
	if err := validatePairingOwner(owner.String(), currentSID, rootSID, isAdmin); err != nil {
		return err
	}
	if err := validatePairingDACLForPrincipal(sd.String(), currentSID, rootSID, isAdmin); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("pairing state path changed during ACL verification")
	}
	return nil
}

func validatePairingOwner(ownerSID, currentSID, rootSID string, isAdmin bool) error {
	if ownerSID == "" || currentSID == "" || rootSID == "" {
		return errors.New("pairing state owner is unavailable")
	}
	if ownerSID == currentSID || ownerSID == windowsSystemSID || ownerSID == windowsAdminSID {
		return nil
	}
	if isAdmin && ownerSID == rootSID {
		// An elevated installer may provision state owned by the dedicated
		// service account; it must already be the root owner's identity.
		return nil
	}
	return errors.New("pairing state owner is outside the authorized service boundary")
}

// Test compatibility wrapper: a self-owned private directory.
func validatePairingDACL(sddl, ownerSID string) error {
	return validatePairingDACLForPrincipal(sddl, ownerSID, ownerSID, false)
}

// Every effective allow ACE must name the active account, the explicitly
// established state-root owner, LocalSystem, or Administrators. Admin-group
// access is usable only with an administrator token. All supported access
// control entries must grant full control, not a misleading partial subset.
// Inherit-only broad ACEs are also rejected because they would expose files.
func validatePairingDACLForPrincipal(sddl, currentSID, rootSID string, isAdmin bool) error {
	start := strings.Index(sddl, "D:")
	if start < 0 || currentSID == "" || rootSID == "" {
		return errors.New("Windows pairing state requires an explicit DACL")
	}
	entries := sddl[start+2:]
	if end := strings.Index(entries, "S:"); end >= 0 {
		entries = entries[:end]
	}
	if !strings.Contains(entries, "(") || strings.Count(entries, "(") != strings.Count(entries, ")") {
		return errors.New("Windows pairing DACL is missing or malformed")
	}
	// Convert SDDL aliases (including LA, the local Administrator account)
	// into native identities. An administrator-group token does not authorize
	// a different local Administrator account.
	current, err := windows.StringToSid(currentSID)
	if err != nil || current == nil || !current.IsValid() {
		return errors.New("invalid Windows pairing current-account SID")
	}
	root, err := windows.StringToSid(rootSID)
	if err != nil || root == nil || !root.IsValid() {
		return errors.New("invalid Windows pairing state-owner SID")
	}
	system, err := windows.StringToSid(windowsSystemSID)
	if err != nil {
		return fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	administrators, err := windows.StringToSid(windowsAdminSID)
	if err != nil {
		return fmt.Errorf("resolve Administrators SID: %w", err)
	}
	grantsCurrent := false
	grantsRoot := false
	for {
		open := strings.IndexByte(entries, '(')
		if open < 0 {
			if strings.Trim(entries, "PAIR") != "" {
				return errors.New("unsupported Windows pairing DACL flags")
			}
			break
		}
		if strings.Trim(entries[:open], "PAIR") != "" {
			return errors.New("unsupported Windows pairing DACL prefix")
		}
		end := strings.IndexByte(entries[open+1:], ')')
		if end < 0 {
			return errors.New("unterminated Windows pairing ACE")
		}
		end += open + 1
		parts := strings.Split(entries[open+1:end], ";")
		if len(parts) != 6 || parts[5] == "" {
			return errors.New("unsupported Windows pairing ACE representation")
		}
		if parts[0] != "A" {
			return errors.New("unsupported Windows pairing ACE type")
		}
		trustee, err := windows.StringToSid(parts[5])
		if err != nil || trustee == nil || !trustee.IsValid() {
			return errors.New("pairing state ACE trustee SID is invalid")
		}
		if !trustee.Equals(current) && !trustee.Equals(root) &&
			!trustee.Equals(system) && !trustee.Equals(administrators) {
			return fmt.Errorf("pairing state grants access to unauthorized SID %s", parts[5])
		}
		if parts[3] != "" || parts[4] != "" {
			return errors.New("unsupported object-specific pairing ACE")
		}
		// Other rights are narrower or ambiguous. No hidden read/write
		// permissions are inferred from inherited or combined ACEs.
		if parts[2] != "FA" && parts[2] != "GA" && parts[2] != "0x1f01ff" && parts[2] != "0x001f01ff" {
			return errors.New("pairing state ACE must grant full control")
		}
		inheritOnly := strings.Contains(parts[1], "IO")
		if !inheritOnly {
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
		return errors.New("pairing DACL does not grant full control to active account and state owner")
	}
	return nil
}

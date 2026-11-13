//go:build windows

package trust

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// All pairing state objects must belong to the service/user SID and have a
// DACL that grants access only to that SID, LocalSystem or Administrators.
// Unknown or inherited broad allow ACEs are rejected, never normalized.
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
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("read pairing process SID: %v", err)
	}
	if !owner.Equals(user.User.Sid) {
		return errors.New("pairing state owner differs from the current process")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("pairing state requires a non-null DACL")
	}
	// x/sys/windows in this repository intentionally pins an older stable
	// version without exported ACE iteration. Convert the OS-owned security
	// descriptor to SDDL, then reject all unsupported or broadly allowed ACEs.
	if err := validatePairingDACL(sd.String(), owner.String()); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("pairing state path changed during ACL verification")
	}
	return nil
}

// validatePairingDACL accepts a strict subset of Windows' canonical SDDL.
// Unknown ACE kinds, malformed entries, or allow entries for any untrusted
// principal cause failure, rather than guessing about effective permissions.
func validatePairingDACL(sddl, ownerSID string) error {
	index := strings.Index(sddl, "D:")
	if index < 0 || ownerSID == "" {
		return errors.New("Windows pairing state requires an explicit DACL")
	}
	entries := sddl[index+2:]
	if end := strings.Index(entries, "S:"); end >= 0 {
		entries = entries[:end]
	}
	if strings.Count(entries, "(") == 0 ||
		strings.Count(entries, "(") != strings.Count(entries, ")") {
		return errors.New("Windows pairing DACL is missing or malformed")
	}
	for {
		start := strings.Index(entries, "(")
		if start < 0 {
			break
		}
		end := strings.Index(entries[start:], ")")
		if end < 0 {
			return errors.New("unterminated Windows pairing ACE")
		}
		end += start
		parts := strings.Split(entries[start+1:end], ";")
		if len(parts) != 6 {
			return errors.New("unsupported Windows pairing ACE representation")
		}
		if strings.Contains(parts[1], "IO") {
			entries = entries[end+1:]
			continue
		}
		switch parts[0] {
		case "D":
			// Deny entries cannot broaden access.
		case "A":
			sid := parts[5]
			if sid != ownerSID && sid != "SY" && sid != "BA" &&
				sid != "S-1-5-18" && sid != "S-1-5-32-544" {
				return fmt.Errorf("Windows pairing DACL grants access to unsupported principal %q", sid)
			}
		default:
			return errors.New("unsupported Windows pairing ACE type")
		}
		entries = entries[end+1:]
	}
	if strings.ContainsAny(entries, "()") {
		return errors.New("malformed trailing Windows pairing DACL")
	}
	return nil
}

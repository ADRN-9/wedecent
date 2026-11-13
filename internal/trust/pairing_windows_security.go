//go:build windows

package trust

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

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
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return fmt.Errorf("inspect pairing ACL entry %d: %v", i, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sid.Equals(user.User.Sid) && sid.String() != "S-1-5-18" &&
				sid.String() != "S-1-5-32-544" {
				return fmt.Errorf("pairing state grants access to unauthorized SID %s", sid.String())
			}
		default:
			return errors.New("unsupported pairing state ACL entry")
		}
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("pairing state path changed during ACL verification")
	}
	return nil
}

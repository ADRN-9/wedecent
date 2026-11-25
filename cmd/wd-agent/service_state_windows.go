//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"wedecent.com/wedecent/internal/trust"
	"wedecent.com/wedecent/internal/winservice"
)

func activeWindowsSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, fmt.Errorf("resolve active service SID: %v", err)
	}
	return user.User.Sid, nil
}

func windowsServiceOwner(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return nil, fmt.Errorf("read service state owner: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil, errors.New("missing service state owner")
	}
	return owner, nil
}

// The installer only provisions empty, private state. Existing identity,
// trust or audit files require explicit operator migration; never rewrite
// exposed key material by granting it a safer DACL after the fact.
func provisionWindowsServiceState(dir, account string) (result error) {
	serviceSID, err := winservice.ResolveServiceAccountSID(account)
	if err != nil {
		return err
	}
	installerSID, err := activeWindowsSID()
	if err != nil {
		return err
	}
	if serviceSID.Equals(installerSID) {
		return errors.New("dedicated service SID must differ from the installer SID")
	}
	for _, builtin := range []string{"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32-544"} {
		sid, err := windows.StringToSid(builtin)
		if err != nil {
			return err
		}
		if serviceSID.Equals(sid) {
			return errors.New("built-in Windows service identity is not a dedicated account")
		}
	}
	admins, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	isAdmin, err := windows.GetCurrentProcessToken().IsMember(admins)
	if err != nil || !isAdmin {
		return errors.New("service state provisioning requires an elevated administrator token")
	}
	_, beforeErr := os.Lstat(dir)
	fresh := errors.Is(beforeErr, os.ErrNotExist)
	if beforeErr != nil && !fresh {
		return beforeErr
	}
	if err := preflightAgentState(dir); err != nil {
		return err
	}
	if err := verifyWindowsServiceStateParent(dir); err != nil {
		return fmt.Errorf("refuse service state under an unprotected parent: %w", err)
	}
	if fresh {
		// Never remove an unrelated directory: clean up only this exact new
		// empty inode on an unsuccessful provisioning attempt. Preexisting
		// directories are never removed or rewritten by this cleanup.
		created, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		defer func() {
			if result == nil {
				return
			}
			current, err := os.Lstat(dir)
			if err == nil && current.IsDir() && os.SameFile(created, current) {
				_ = os.Remove(dir) // only succeeds when still empty
			}
		}()
	}
	guard, err := guardWindowsServiceState(dir)
	if err != nil {
		return err
	}
	defer guard()
	// Re-verify the protected parent and exact directory after acquiring
	// handles, before any owner/DACL mutation or sensitive file creation.
	if err := verifyWindowsServiceStateParent(dir); err != nil {
		return fmt.Errorf("revalidate protected service state parent: %w", err)
	}
	if err := verifyWindowsStateForSID(dir, installerSID); err != nil {
		return fmt.Errorf("revalidate installer-owned service state under path guard: %w", err)
	}
	if err := requireEmptyWindowsServiceState(dir); err != nil {
		return err
	}
	if err := winservice.RestrictDirectory(dir, account); err != nil {
		return fmt.Errorf("secure dedicated service ownership: %w", err)
	}
	if err := verifyWindowsStateForSID(dir, serviceSID); err != nil {
		return fmt.Errorf("verify provisioned dedicated service state: %w", err)
	}
	return nil
}

func requireEmptyWindowsServiceState(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("existing service state is not empty: explicit offline migration and re-enrollment required")
	}
	return nil
}

func verifyWindowsServiceStateParent(dir string) error {
	root, _, err := windowsStatePathComponents(dir)
	if err != nil {
		return err
	}
	parent := filepath.Clean(filepath.Dir(dir))
	if strings.EqualFold(parent, filepath.Clean(root)) {
		return nil
	}
	if _, err := inspectWindowsStateDirectory(parent); err != nil {
		return fmt.Errorf("inspect service state parent: %w", err)
	}
	owner, err := windowsServiceOwner(parent)
	if err != nil {
		return fmt.Errorf("read service state parent owner: %w", err)
	}
	current, err := activeWindowsSID()
	if err != nil {
		return err
	}
	trustedOwners := []string{
		"S-1-5-18",
		"S-1-5-32-544",
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
	}
	ownerTrusted := owner.Equals(current)
	for _, sidText := range trustedOwners {
		sid, err := windows.StringToSid(sidText)
		if err != nil {
			return err
		}
		if owner.Equals(sid) {
			ownerTrusted = true
			break
		}
	}
	if !ownerTrusted {
		return fmt.Errorf("service state parent owner %s is not the installer or a trusted Windows principal", owner)
	}
	if err := trust.VerifyPairingStatePath(parent); err != nil {
		return fmt.Errorf("service state parent must have a protected owner and DACL: %w", err)
	}
	return nil
}

func verifyWindowsStateForSID(dir string, required *windows.SID) error {
	root, components, err := windowsStatePathComponents(dir)
	if err != nil {
		return err
	}
	if err := requireLocalNTFS(root); err != nil {
		return err
	}
	at := root
	if _, err := inspectWindowsStateDirectory(at); err != nil {
		return err
	}
	for _, name := range components {
		at = filepath.Join(at, name)
		if _, err := inspectWindowsStateDirectory(at); err != nil {
			return err
		}
	}
	if err := trust.VerifyPairingStatePath(dir); err != nil {
		return err
	}
	owner, err := windowsServiceOwner(dir)
	if err != nil {
		return err
	}
	if !owner.Equals(required) {
		return fmt.Errorf("service state owner %s differs from the configured service account %s", owner, required)
	}
	return nil
}

func verifyWindowsServiceState(dir string) error {
	current, err := activeWindowsSID()
	if err != nil {
		return err
	}
	return verifyWindowsStateForSID(dir, current)
}

func verifyWindowsServiceFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("service log must be a real regular file")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("service log is a redirected or inaccessible file")
	}
	if err := trust.VerifyPairingStatePath(path); err != nil {
		return err
	}
	owner, err := windowsServiceOwner(path)
	if err != nil {
		return err
	}
	current, err := activeWindowsSID()
	if err != nil {
		return err
	}
	if !owner.Equals(current) {
		return errors.New("service log is owned by a different account")
	}
	return nil
}

// Keep handles on every component and compare object identity across open.
// Windows permits a directory owner to rename an open directory through its
// parent, so these handles are not an ACL substitute. Service provisioning
// requires a protected parent DACL; startup revalidates the pathname and ACL.
func guardWindowsServiceState(dir string) (func(), error) {
	root, components, err := windowsStatePathComponents(dir)
	if err != nil {
		return nil, err
	}
	var held []*os.File
	closeAll := func() {
		for i := len(held) - 1; i >= 0; i-- {
			_ = held[i].Close()
		}
	}
	paths := []string{root}
	at := root
	for _, component := range components {
		at = filepath.Join(at, component)
		paths = append(paths, at)
	}
	for _, path := range paths {
		before, err := inspectWindowsStateDirectory(path)
		if err != nil {
			closeAll()
			return nil, err
		}
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			closeAll()
			return nil, err
		}
		h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("hold service state directory %q: %w", path, err)
		}
		f := os.NewFile(uintptr(h), path)
		held = append(held, f)
		opened, err := f.Stat()
		if err != nil {
			closeAll()
			return nil, err
		}
		after, err := inspectWindowsStateDirectory(path)
		if err != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
			closeAll()
			return nil, fmt.Errorf("service directory changed during protected open: %s", path)
		}
	}
	return closeAll, nil
}

func createWindowsServiceLog(path string) (*os.File, error) {
	current, err := activeWindowsSID()
	if err != nil {
		return nil, err
	}
	sid := current.String()
	sd, err := windows.SecurityDescriptorFromString(
		"O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		&sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

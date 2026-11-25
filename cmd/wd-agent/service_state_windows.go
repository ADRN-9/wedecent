//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	if err := preflightWindowsAgentState(dir, windowsStateProvisionHooks{ownerSID: admins}); err != nil {
		return err
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
	if err := verifyWindowsServiceStateParent(dir); err != nil {
		return fmt.Errorf("refuse service state under an unprotected parent: %w", err)
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
	if err := verifyWindowsStateForSID(dir, admins); err != nil {
		return fmt.Errorf("revalidate administrator-owned service state under path guard: %w", err)
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
	root, components, err := windowsStatePathComponents(dir)
	if err != nil {
		return err
	}
	if err := verifyWindowsStateAncestorOwners(root, components, nil, nil); err != nil {
		return fmt.Errorf("verify state ancestor ownership: %w", err)
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
	trustedOwners := []string{
		"S-1-5-18",
		"S-1-5-32-544",
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
	}
	ownerTrusted := false
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
		return fmt.Errorf("service state parent owner %s is not a trusted Windows principal", owner)
	}
	if err := trust.VerifyPairingStatePath(parent); err != nil {
		return fmt.Errorf("service state parent must have a protected owner and DACL: %w", err)
	}
	return nil
}

const windowsAncestorMutationRights = uint32(
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		0x00000040 | // FILE_DELETE_CHILD
		0x00000002 | // FILE_ADD_FILE / FILE_WRITE_DATA
		0x00000004 | // FILE_ADD_SUBDIRECTORY / FILE_APPEND_DATA
		0x00000010 | // FILE_WRITE_EA
		0x00000100 | // FILE_WRITE_ATTRIBUTES
		windows.GENERIC_WRITE | windows.GENERIC_ALL,
)

// Every directory traversed to reach protected state must reject mutation
// rights for untrusted principals. This is deliberately stricter than
// checking only the final state directory: FILE_DELETE_CHILD on any parent
// permits replacement of a descendant pathname.
func verifyWindowsStateAncestors(root string, components []string, required *windows.SID) error {
	active, err := activeWindowsSID()
	if err != nil {
		return err
	}
	// Owner trust is an explicit SID allowlist. Never derive trust from the
	// owner of the path currently being inspected.
	if err := verifyWindowsStateAncestorOwners(root, components, active, required); err != nil {
		return err
	}
	trusted := map[string]bool{
		active.String(): true,
		"S-1-5-18":      true,
		"S-1-5-32-544":  true,
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
	}
	if required != nil {
		trusted[required.String()] = true
	}
	path := root
	for i := 0; i < len(components); i++ {
		if err := verifyWindowsStateAncestorDirectory(path, trusted); err != nil {
			return fmt.Errorf("untrusted state ancestor %q: %w", path, err)
		}
		path = filepath.Join(path, components[i])
	}
	return nil
}

func verifyWindowsStateAncestorDirectory(path string, trusted map[string]bool) error {
	return verifyWindowsStateAncestorDirectoryWithRights(path, trusted, windowsAncestorMutationRights)
}

const windowsMigrationAncestorMutationRights uint32 = windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	0x00000040 | // FILE_DELETE_CHILD
	windows.GENERIC_ALL

// Legacy state may live below ProgramData, whose inherited DACL commonly
// permits creating new children. Migration only needs to reject rights that
// can replace or retake control of an existing protected descendant.
func verifyWindowsMigrationAncestorDirectory(path string, trusted map[string]bool) error {
	return verifyWindowsStateAncestorDirectoryWithRights(path, trusted, windowsMigrationAncestorMutationRights)
}

func verifyWindowsStateAncestorDirectoryWithRights(path string, trusted map[string]bool, mutationRights uint32) error {
	if _, err := inspectWindowsStateDirectory(path); err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("read ancestor DACL: %v", err)
	}
	sddl := sd.String()
	start := strings.Index(sddl, "D:")
	if start < 0 {
		return errors.New("ancestor requires an explicit DACL")
	}
	entries := sddl[start+2:]
	if end := strings.Index(entries, "S:"); end >= 0 {
		entries = entries[:end]
	}
	if !strings.Contains(entries, "(") || strings.Count(entries, "(") != strings.Count(entries, ")") {
		return errors.New("ancestor DACL is missing or malformed")
	}
	for {
		open := strings.IndexByte(entries, '(')
		if open < 0 {
			if strings.Trim(entries, "PAIR") != "" {
				return errors.New("unsupported ancestor DACL flags")
			}
			break
		}
		if strings.Trim(entries[:open], "PAIR") != "" {
			return errors.New("unsupported ancestor DACL prefix")
		}
		close := strings.IndexByte(entries[open+1:], ')')
		if close < 0 {
			return errors.New("unterminated ancestor DACL ACE")
		}
		close += open + 1
		parts := strings.Split(entries[open+1:close], ";")
		if len(parts) != 6 || parts[5] == "" {
			return errors.New("unsupported ancestor DACL ACE representation")
		}
		if parts[0] == "D" {
			entries = entries[close+1:]
			continue
		}
		if parts[0] != "A" {
			return errors.New("unsupported ancestor DACL ACE type")
		}
		if strings.Contains(parts[1], "IO") {
			entries = entries[close+1:]
			continue
		}
		trustee, err := windows.StringToSid(parts[5])
		if err != nil || trustee == nil || !trustee.IsValid() {
			return errors.New("ancestor DACL contains an invalid trustee SID")
		}
		if !trusted[trustee.String()] {
			mask, err := windowsSDDLRightsMask(parts[2])
			if err != nil {
				return fmt.Errorf("parse ancestor DACL rights: %w", err)
			}
			if mask&mutationRights != 0 {
				return fmt.Errorf("ancestor grants pathname mutation rights %s to untrusted SID %s", parts[2], trustee)
			}
		}
		entries = entries[close+1:]
	}
	return nil
}

func windowsSDDLRightsMask(rights string) (uint32, error) {
	if strings.HasPrefix(rights, "0x") {
		mask, err := strconv.ParseUint(strings.TrimPrefix(rights, "0x"), 16, 32)
		return uint32(mask), err
	}
	codes := map[string]uint32{
		"FA": 0x001F01FF,
		"GA": windows.GENERIC_ALL,
		"GW": windows.GENERIC_WRITE,
		"FW": 0x00000002,
		"AD": 0x00000004,
		"CC": 0x00000004,
		"DC": 0x00000040,
		"DE": windows.DELETE,
		"SD": windows.DELETE,
		"DT": windows.DELETE,
		"WD": windows.WRITE_DAC,
		"WO": windows.WRITE_OWNER,
		"FR": 0,
		"FX": 0,
		"GR": 0,
		"GX": 0,
		"RC": 0,
		"RP": 0,
		"RD": 0,
		"RE": 0,
		"RA": 0,
		"X":  0,
		"LC": 0,
		"LO": 0,
		"WP": windows.WRITE_DAC,
		"SW": windows.WRITE_DAC,
		"CR": windows.WRITE_DAC,
		"AS": windows.WRITE_DAC,
		"MA": windows.GENERIC_ALL,
		"WA": 0x00000100,
		"WE": 0x00000010,
	}
	var mask uint32
	if len(rights)%2 != 0 {
		return 0, errors.New("invalid SDDL rights token")
	}
	for i := 0; i < len(rights); i += 2 {
		code := rights[i : i+2]
		value, ok := codes[code]
		if !ok {
			return 0, fmt.Errorf("unsupported SDDL rights token %q", code)
		}
		mask |= value
	}
	return mask, nil
}

var windowsStateAncestorOwnerLookup = windowsServiceOwner

func verifyWindowsStateAncestorOwners(root string, components []string, installer, required *windows.SID) error {
	allowed := make(map[string]bool)
	if installer != nil {
		allowed[installer.String()] = true
	}
	if required != nil {
		allowed[required.String()] = true
	}
	for _, sidText := range []string{
		"S-1-5-18",
		"S-1-5-32-544",
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
	} {
		allowed[sidText] = true
	}
	path := root
	for i := 0; i < len(components); i++ {
		owner, err := windowsStateAncestorOwnerLookup(path)
		if err != nil {
			return fmt.Errorf("read state ancestor owner %q: %w", path, err)
		}
		if owner == nil || !owner.IsValid() {
			return fmt.Errorf("read state ancestor owner %q: missing or invalid owner SID", path)
		}
		if !allowed[owner.String()] {
			return fmt.Errorf("state ancestor %q is owned by untrusted SID %s", path, owner)
		}
		path = filepath.Join(path, components[i])
	}
	return nil
}

// verifyMigrationSourceForSID is deliberately narrower than normal service
// startup validation. It accepts legacy ancestors with benign inherited
// create-child permissions, but rejects any untrusted ability to delete,
// replace, take ownership of, or rewrite the DACL of an ancestor.
func verifyMigrationSourceForSID(dir, serviceSID string) error {
	required, err := windows.StringToSid(serviceSID)
	if err != nil || required == nil || !required.IsValid() {
		return errors.New("migration service SID is invalid")
	}
	root, components, err := windowsStatePathComponents(dir)
	if err != nil {
		return err
	}
	if len(components) == 0 {
		return errors.New("migration source cannot be a volume root")
	}
	if err := requireLocalNTFS(root); err != nil {
		return err
	}
	active, err := activeWindowsSID()
	if err != nil {
		return err
	}
	trusted := map[string]bool{
		active.String(): true,
		required.String(): true,
		"S-1-5-18": true,
		"S-1-5-32-544": true,
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
	}
	path := root
	for i := 0; i < len(components); i++ {
		if err := verifyWindowsMigrationAncestorDirectory(path, trusted); err != nil {
			return fmt.Errorf("untrusted legacy migration ancestor %q: %w", path, err)
		}
		owner, err := windowsStateAncestorOwnerLookup(path)
		if err != nil || owner == nil || !owner.IsValid() || !trusted[owner.String()] {
			return fmt.Errorf("legacy migration ancestor %q has an untrusted owner: %v", path, err)
		}
		path = filepath.Join(path, components[i])
	}
	if _, err := inspectWindowsStateDirectory(path); err != nil {
		return fmt.Errorf("inspect legacy migration source: %w", err)
	}
	if err := trust.VerifyPairingStatePath(path); err != nil {
		return fmt.Errorf("legacy migration source DACL is not protected: %w", err)
	}
	owner, err := windowsServiceOwner(path)
	if err != nil || !owner.Equals(required) {
		return fmt.Errorf("legacy migration source owner does not match dedicated service SID: %v", err)
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
	if err := verifyWindowsStateAncestors(root, components, required); err != nil {
		return fmt.Errorf("verify protected state ancestors: %w", err)
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

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
)

type windowsStateProvisionHooks struct {
	afterCreate func(string) error
	ownerSID    *windows.SID
}

type windowsStateComponent struct {
	path string
	info os.FileInfo
}

// preflightAgentState creates missing directories with a protected DACL at
// creation time. Existing state is validated, never repaired in place.
func preflightAgentState(dir string) error {
	return preflightWindowsAgentState(dir, windowsStateProvisionHooks{})
}

func preflightWindowsAgentState(dir string, hooks windowsStateProvisionHooks) (result error) {
	root, components, err := windowsStatePathComponents(dir)
	if err != nil {
		return fmt.Errorf("agent state security preflight: %w", err)
	}
	if err := requireLocalNTFS(root); err != nil {
		return fmt.Errorf("agent state security preflight: %w", err)
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return fmt.Errorf("agent state security preflight: resolve active Windows SID: %v", err)
	}
	ownerSID := current.User.Sid
	if hooks.ownerSID != nil {
		ownerSID = hooks.ownerSID
	}
	sid := ownerSID.String()
	sd, err := windows.SecurityDescriptorFromString(
		"O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return fmt.Errorf("agent state security preflight: construct protected DACL: %w", err)
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}

	// Every new component is created with the private descriptor, even when
	// an existing ancestor has inherited broad access. Never chmod ancestors.
	var seen []windowsStateComponent
	var created []windowsStateComponent
	defer func() {
		if result == nil {
			return
		}
		for i := len(created) - 1; i >= 0; i-- {
			item := created[i]
			now, err := os.Lstat(item.path)
			if err == nil && now.IsDir() && now.Mode()&os.ModeSymlink == 0 &&
				os.SameFile(item.info, now) {
				// Remove only the same empty directory this call created.
				// Concurrent writers may make it nonempty; then retain it.
				_ = os.Remove(item.path)
			}
		}
	}()

	at := root
	if info, err := inspectWindowsStateDirectory(at); err != nil {
		return fmt.Errorf("agent state security preflight: volume root: %w", err)
	} else {
		seen = append(seen, windowsStateComponent{path: at, info: info})
	}
	for _, component := range components {
		at = filepath.Join(at, component)
		info, err := inspectWindowsStateDirectory(at)
		if errors.Is(err, os.ErrNotExist) {
			path, e := windows.UTF16PtrFromString(at)
			if e != nil {
				return fmt.Errorf("agent state security preflight: invalid path: %w", e)
			}
			e = windows.CreateDirectory(path, &sa)
			runtime.KeepAlive(sd)
			if e != nil && !errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
				return fmt.Errorf("agent state security preflight: create protected directory: %w", e)
			}
			info, err = inspectWindowsStateDirectory(at)
			if err == nil && e == nil {
				created = append(created, windowsStateComponent{path: at, info: info})
			}
			if err == nil && e == nil && hooks.afterCreate != nil {
				if hookErr := hooks.afterCreate(at); hookErr != nil {
					return fmt.Errorf("agent state security preflight: post-create verification: %w", hookErr)
				}
			}
			if err == nil && e == nil {
				// No identity, trust or pairing material can be created unless
				// every newly provisioned directory passes the shared ACL gate.
				err = trust.VerifyPairingStatePath(at)
			}
		}
		if err != nil {
			return fmt.Errorf("agent state security preflight: inspect directory %q: %w", at, err)
		}
		seen = append(seen, windowsStateComponent{path: at, info: info})
	}
	if err := trust.VerifyPairingStatePath(at); err != nil {
		return fmt.Errorf("agent state security preflight: %w", err)
	}
	// Dedicated service identities are accepted when actually executing under
	// that SID. Elevated installers use winservice.RestrictDirectory to
	// provision a different account, never an arbitrary foreign state owner.
	if err := verifyWindowsAgentStateOwner(at, ownerSID); err != nil {
		return fmt.Errorf("agent state security preflight: %w", err)
	}
	for _, item := range seen {
		now, err := inspectWindowsStateDirectory(item.path)
		if err != nil || !os.SameFile(item.info, now) {
			return fmt.Errorf("agent state security preflight: directory changed during creation: %s", item.path)
		}
	}
	return nil
}

// Strict drive-absolute, literal paths only: no UNC/device namespace, relative
// drive, dot segments, alternate data streams, reserved devices or aliases.
func windowsStatePathComponents(dir string) (string, []string, error) {
	if dir == "" || !filepath.IsAbs(dir) || strings.HasPrefix(dir, `\\`) {
		return "", nil, errors.New("Windows agent state requires an absolute local drive path")
	}
	raw := strings.ReplaceAll(dir, "/", `\`)
	volume := filepath.VolumeName(raw)
	if len(volume) != 2 || volume[1] != ':' || !((volume[0] >= 'A' && volume[0] <= 'Z') ||
		(volume[0] >= 'a' && volume[0] <= 'z')) || len(raw) < 4 || raw[2] != '\\' {
		return "", nil, errors.New("Windows agent state requires an unambiguous drive-letter path")
	}
	parts := strings.Split(raw[3:], `\`)
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") ||
			strings.HasSuffix(part, " ") || strings.ContainsAny(part, `<>:"|?*`) {
			return "", nil, fmt.Errorf("unsafe Windows agent state path component %q", part)
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			(len(base) == 4 && ((strings.HasPrefix(base, "COM") && base[3] >= '1' && base[3] <= '9') ||
				(strings.HasPrefix(base, "LPT") && base[3] >= '1' && base[3] <= '9'))) {
			return "", nil, errors.New("reserved Windows state path component")
		}
	}
	return volume + `\`, parts, nil
}

func inspectWindowsStateDirectory(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("agent state path is not a real directory")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return nil, err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("agent state path is a junction or reparse point")
	}
	return info, nil
}

func requireLocalNTFS(root string) error {
	name, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	if driveType := windows.GetDriveType(name); driveType != windows.DRIVE_FIXED {
		return fmt.Errorf("agent state requires a local fixed drive (type=%d)", driveType)
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("agent state volume root is a reparse point")
	}
	var fs [32]uint16
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))); err != nil {
		return err
	}
	if !strings.EqualFold(windows.UTF16ToString(fs[:]), "NTFS") {
		return errors.New("agent state requires local NTFS")
	}
	return nil
}

func verifyWindowsAgentStateOwner(path string, current *windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("read Windows agent state owner: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("Windows agent state owner is unavailable")
	}
	if !windowsAgentStateOwnerAllowed(owner, current) {
		return errors.New("agent state owner does not match the active or supported system identity")
	}
	return nil
}

func windowsAgentStateOwnerAllowed(owner, active *windows.SID) bool {
	if owner == nil || active == nil {
		return false
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return false
	}
	admins, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return false
	}
	return owner.Equals(active) || owner.Equals(system) || owner.Equals(admins)
}

func verifyMigrationStateParent(path string) error {
	return verifyWindowsServiceStateParent(path)
}

func verifyMigrationStateForSID(path, serviceSID string) error {
	sid, err := windows.StringToSid(serviceSID)
	if err != nil || sid == nil || !sid.IsValid() {
		return errors.New("migration service SID is invalid")
	}
	return verifyWindowsStateForSID(path, sid)
}

func verifyMigrationParentForProvisioning(path string) error {
	root, components, err := windowsStatePathComponents(path)
	if err != nil {
		return err
	}
	if len(components) < 2 {
		return errors.New("migration parent path is too close to the volume root")
	}
	if err := requireLocalNTFS(root); err != nil {
		return err
	}
	if err := verifyWindowsStateAncestors(root, components[:len(components)-1], nil); err != nil {
		return fmt.Errorf("verify migration parent ancestors: %w", err)
	}
	parent := filepath.Clean(filepath.Dir(path))
	if _, err := inspectWindowsStateDirectory(parent); err != nil {
		return fmt.Errorf("inspect migration parent: %w", err)
	}
	owner, err := windowsServiceOwner(parent)
	if err != nil {
		return err
	}
	active, err := activeWindowsSID()
	if err != nil {
		return err
	}
	allowed := map[string]bool{
		active.String(): true,
		"S-1-5-18":      true,
		"S-1-5-32-544":  true,
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
	}
	if !allowed[owner.String()] {
		return fmt.Errorf("migration parent owner %s is not trusted for protected ACL provisioning", owner)
	}
	return nil
}

//go:build windows

package portforward

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func setReplayFileOwner(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		user.User.Sid,
		nil,
		nil,
		nil,
	)
}

func prepareReplayDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		return secureReplayDirectory(path)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid
	sddl := fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", sid.String(), sid.String())
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner,
		nil,
		dacl,
		nil,
	); err != nil {
		return err
	}
	return secureReplayDirectory(path)
}

func secureReplayDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("replay directory must be a real directory")
	}
	return verifyReplayACL(path)
}

func secureReplayFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("replay file must be a regular file")
	}
	return verifyReplayACL(path)
}

func verifyReplayACL(path string) error {
	return verifyReplayACLMode(path, true)
}

// verifyReplayDACL checks the access list before repairing an orphaned owner.
// It never changes a descriptor that grants access to an untrusted SID.
func verifyReplayDACL(path string) error {
	return verifyReplayACLMode(path, false)
}

func verifyReplayACLMode(path string, requireCurrentOwner bool) error {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read replay ACL: %w", err)
	}
	if sd == nil {
		return errors.New("replay object security descriptor is unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read replay object owner: %w", err)
	}
	if owner == nil {
		return errors.New("replay object owner is unavailable")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current user SID: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return errors.New("current user SID is unavailable")
	}
	if requireCurrentOwner && !windows.EqualSid(owner, user.User.Sid) {
		return errors.New("replay object is not owned by the current user")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read replay object DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("replay object has no restrictive DACL")
	}
	allowed := map[string]bool{
		user.User.Sid.String(): true,
		"S-1-5-18":             true,
		"S-1-5-32-544":         true,
		"SY":                   true,
		"BA":                   true,
		"LA":                   true, // Local Administrator is a privileged administrator SID.
		"CO":                   true,
		"OW":                   true,
	}
	sddl := sd.String()
	start := strings.Index(sddl, "D:")
	if start < 0 {
		return fmt.Errorf("replay object DACL is missing")
	}
	section := sddl[start+2:]
	if end := strings.Index(section, "S:"); end >= 0 {
		section = section[:end]
	}
	firstACE := strings.Index(section, "(")
	if firstACE < 0 {
		return fmt.Errorf("replay object DACL is empty")
	}
	section = section[firstACE:]
	if section == "" {
		return fmt.Errorf("replay object DACL is empty")
	}
	aceCount := 0
	for len(section) > 0 {
		open := strings.Index(section, "(")
		if open < 0 {
			break
		}
		close := strings.Index(section[open+1:], ")")
		if close < 0 {
			return fmt.Errorf("replay object DACL is malformed")
		}
		fields := strings.Split(section[open+1:open+1+close], ";")
		ace := section[open+1 : open+1+close]
		if len(fields) != 6 || fields[0] != "A" || !allowed[fields[5]] {
			return fmt.Errorf("replay object DACL grants access outside the current user, SYSTEM and Administrators (ACE %q; DACL %q)", ace, sd.String())
		}
		aceCount++
		section = section[open+close+2:]
	}
	if aceCount == 0 {
		return fmt.Errorf("replay object DACL contains no access entries")
	}
	return nil
}

func openReplayBootstrapLockHandle(lockPath string) (*os.File, bool, error) {
	name, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, false, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	created := err == nil
	if err != nil {
		if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, false, err
		}
		handle, err = windows.CreateFile(
			name,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if err != nil {
			return nil, false, err
		}
	}
	return os.NewFile(uintptr(handle), lockPath), created, nil
}

// lockReplayBootstrapFile serializes lock-file publication and all cleanup of
// lock-bootstrap staging files. The handle denies delete sharing so its path
// cannot be replaced while another process is using it.
func lockReplayBootstrapFile(path string) (func() error, error) {
	bootstrapPath := path + ".lock.bootstrap"
	file, _, err := openReplayBootstrapLockHandle(bootstrapPath)
	if err != nil {
		return nil, fmt.Errorf("open replay bootstrap lock: %w", err)
	}
	closeWithError := func(primary error) error {
		return errors.Join(primary, file.Close())
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, closeWithError(err)
	}
	pathInfo, err := os.Lstat(bootstrapPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() ||
		!openedInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		return nil, closeWithError(fmt.Errorf("replay bootstrap lock changed during open"))
	}
	if err := verifyReplayDACL(bootstrapPath); err != nil {
		return nil, closeWithError(fmt.Errorf("refuse bootstrap lock with unauthorized DACL: %w", err))
	}
	// Repair an orphan whose creator crashed between CREATE_NEW and owner
	// assignment, but only after proving the existing DACL is restrictive.
	if err := setReplayFileOwner(bootstrapPath); err != nil {
		return nil, closeWithError(fmt.Errorf("set replay bootstrap lock owner: %w", err))
	}
	if err := secureReplayFile(bootstrapPath); err != nil {
		return nil, closeWithError(err)
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return nil, closeWithError(fmt.Errorf("lock replay bootstrap: %w", err))
	}
	return func() error {
		return errors.Join(
			windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped),
			file.Close(),
		)
	}, nil
}

func openReplayLockHandle(lockPath string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), lockPath), nil
}

func openReplayLockFile(lockPath string) (*os.File, bool, error) {
	if _, err := os.Lstat(lockPath); err == nil {
		file, openErr := openReplayLockHandle(lockPath)
		return file, false, openErr
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}

	storePath := strings.TrimSuffix(lockPath, ".lock")
	if storePath == lockPath {
		return nil, false, fmt.Errorf("invalid replay lock path")
	}
	temp, err := os.CreateTemp(filepath.Dir(lockPath), replayStagingPattern(storePath, "lock"))
	if err != nil {
		return nil, false, err
	}
	tempPath := temp.Name()
	cleanup := func(primary error) error {
		return cleanupReplayTemp(primary, temp, tempPath)
	}
	if err := temp.Chmod(0o600); err != nil {
		return nil, false, cleanup(err)
	}
	if err := setReplayFileOwner(tempPath); err != nil {
		return nil, false, cleanup(fmt.Errorf("set replay lock owner: %w", err))
	}
	if err := secureReplayFile(tempPath); err != nil {
		return nil, false, cleanup(err)
	}
	if err := temp.Sync(); err != nil {
		return nil, false, cleanup(err)
	}
	if err := temp.Close(); err != nil {
		return nil, false, cleanupReplayTemp(err, nil, tempPath)
	}
	if err := createReplayFileExclusive(tempPath, lockPath); err != nil {
		cleanupErr := removeReplayTemp(tempPath)
		if os.IsExist(err) {
			file, openErr := openReplayLockHandle(lockPath)
			if cleanupErr != nil {
				if file != nil {
					cleanupErr = errors.Join(cleanupErr, file.Close())
				}
				return nil, false, errors.Join(cleanupErr, openErr)
			}
			return file, false, openErr
		}
		return nil, false, errors.Join(err, cleanupErr)
	}
	file, err := openReplayLockHandle(lockPath)
	if err != nil {
		return nil, true, err
	}
	return file, true, nil
}

func lockReplayFileOS(path string) (unlock func() error, created bool, retErr error) {
	dir := filepath.Dir(path)
	if err := secureReplayDirectory(dir); err != nil {
		return nil, false, err
	}
	bootstrapUnlock, err := lockReplayBootstrapFile(path)
	if err != nil {
		return nil, false, err
	}
	bootstrapHeld := true
	defer func() {
		if bootstrapHeld {
			retErr = errors.Join(retErr, bootstrapUnlock())
		}
	}()
	lockPath := path + ".lock"
	_, anchorErr := os.Lstat(path + ".anchor")
	_, stateErr := os.Lstat(path)
	_, lockErr := os.Lstat(lockPath)
	lockMissing := os.IsNotExist(lockErr)
	if lockMissing && (!os.IsNotExist(anchorErr) || !os.IsNotExist(stateErr)) {
		return nil, false, fmt.Errorf("replay lock was deleted after initialization")
	}
	if lockErr == nil {
		if err := secureReplayFile(lockPath); err != nil {
			return nil, false, err
		}
	} else if !lockMissing {
		return nil, false, lockErr
	}

	file, created, err := openReplayLockFile(lockPath)
	if err != nil {
		return nil, false, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, false, errors.Join(err, file.Close())
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return nil, false, errors.Join(fmt.Errorf("replay lock changed during open"), file.Close())
	}
	if err := secureReplayFile(lockPath); err != nil {
		return nil, false, errors.Join(err, file.Close())
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return nil, false, errors.Join(fmt.Errorf("lock replay store: %w", err), file.Close())
	}
	bootstrapHeld = false
	return func() error {
		return errors.Join(
			windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped),
			file.Close(),
			bootstrapUnlock(),
		)
	}, created, nil
}

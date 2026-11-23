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
	if user == nil || user.User.Sid == nil || !windows.EqualSid(owner, user.User.Sid) {
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
		owner.String(): true,
		"S-1-5-18":     true,
		"S-1-5-32-544": true,
		"SY":           true,
		"BA":           true,
		"LA":           true, // Local Administrator is a privileged administrator SID.
		"CO":           true,
		"OW":           true,
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

	temp, err := os.CreateTemp(filepath.Dir(lockPath), ".portforward-lock-*")
	if err != nil {
		return nil, false, err
	}
	tempPath := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return nil, false, err
	}
	if err := setReplayFileOwner(tempPath); err != nil {
		cleanup()
		return nil, false, fmt.Errorf("set replay lock owner: %w", err)
	}
	if err := secureReplayFile(tempPath); err != nil {
		cleanup()
		return nil, false, err
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return nil, false, err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return nil, false, err
	}
	if err := createReplayFileExclusive(tempPath, lockPath); err != nil {
		_ = os.Remove(tempPath)
		if os.IsExist(err) {
			file, openErr := openReplayLockHandle(lockPath)
			return file, false, openErr
		}
		return nil, false, err
	}
	file, err := openReplayLockHandle(lockPath)
	if err != nil {
		return nil, true, err
	}
	return file, true, nil
}

func lockReplayFileOS(path string) (func(), bool, error) {
	dir := filepath.Dir(path)
	if err := secureReplayDirectory(dir); err != nil {
		return nil, false, err
	}
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
		_ = file.Close()
		return nil, false, err
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		_ = file.Close()
		return nil, false, fmt.Errorf("replay lock changed during open")
	}
	if err := secureReplayFile(lockPath); err != nil {
		_ = file.Close()
		return nil, false, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		_ = file.Close()
		return nil, false, fmt.Errorf("lock replay store: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
		_ = file.Close()
	}, created, nil
}

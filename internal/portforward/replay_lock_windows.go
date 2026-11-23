//go:build windows

package portforward

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

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
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("replay object owner is unavailable: %w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !owner.Equals(user.User.Sid) {
		return fmt.Errorf("replay object is not owned by the current user: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("replay object has no restrictive DACL: %w", err)
	}
	allowed := map[string]bool{
		owner.String():       true,
		"S-1-5-18":          true, // LocalSystem
		"S-1-5-32-544":      true, // Builtin Administrators
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
	section = section[strings.Index(section, "("):]
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
		if len(fields) != 6 || fields[0] != "A" || !allowed[fields[5]] {
			return fmt.Errorf("replay object DACL grants access outside the current user, SYSTEM and Administrators")
		}
		aceCount++
		section = section[open+close+2:]
	}
	if aceCount == 0 {
		return fmt.Errorf("replay object DACL contains no access entries")
	}
	return nil
}

func lockReplayFile(path string) (func(), bool, error) {
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

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	created := true
	if os.IsExist(err) {
		created = false
		file, err = os.OpenFile(lockPath, os.O_RDWR, 0o600)
	}
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
	if created {
		_, anchorErr = os.Lstat(path + ".anchor")
		_, stateErr = os.Lstat(path)
		if !os.IsNotExist(anchorErr) || !os.IsNotExist(stateErr) {
			_ = file.Close()
			return nil, false, fmt.Errorf("replay lock was recreated for an existing store")
		}
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

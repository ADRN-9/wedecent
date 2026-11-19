//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// ReadPrivateFile reads a bounded regular file without following a reparse
// point. The file must be owned by the current user and have a narrow DACL.
func ReadPrivateFile(path string, maxBytes int64) ([]byte, error) {
	if path == "" || maxBytes < 1 {
		return nil, errors.New("private file path and positive size limit are required")
	}
	lowerPath := strings.ToLower(path)
	if strings.HasPrefix(lowerPath, `\\.\pipe\`) || strings.HasPrefix(lowerPath, `\\?\pipe\`) {
		return nil, errors.New("private file path must not name a Windows named pipe")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open private file without following reparse points: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("open private file returned an invalid handle")
	}
	defer file.Close()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, fmt.Errorf("inspect private file handle: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("private file must not be a reparse point")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return nil, errors.New("private file must be a regular file")
	}
	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat private file: %w", err)
	}
	if !stat.Mode().IsRegular() || stat.Size() > maxBytes {
		return nil, errors.New("private file must be a regular file within the size limit")
	}
	if err := validatePrivateFileSecurity(path); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read private file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		clear(data)
		return nil, errors.New("private file exceeds size limit")
	}
	return data, nil
}

func validatePrivateFileSecurity(path string) error {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || sd == nil {
		return fmt.Errorf("read private file security descriptor: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("private file owner is unavailable")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("private file requires a non-null DACL")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return errors.New("current Windows user SID is unavailable")
	}
	currentSID := user.User.Sid.String()
	if err := validatePrivateFileOwner(owner.String(), currentSID); err != nil {
		return err
	}
	return validatePrivateFileDACL(sd.String(), currentSID)
}

func validatePrivateFileOwner(owner, current string) error {
	if owner == "" || current == "" || owner != current {
		return errors.New("private file must be owned by the current user")
	}
	return nil
}

func validatePrivateFileDACL(sddl, currentSID string) error {
	start := strings.Index(sddl, "D:")
	if start < 0 || currentSID == "" {
		return errors.New("private file requires an explicit DACL")
	}
	entries := sddl[start+2:]
	if end := strings.Index(entries, "S:"); end >= 0 {
		entries = entries[:end]
	}
	if !strings.Contains(entries, "(") || strings.Count(entries, "(") != strings.Count(entries, ")") {
		return errors.New("private file DACL is missing or malformed")
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	admins, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	current, err := windows.StringToSid(currentSID)
	if err != nil {
		return errors.New("current Windows user SID is invalid")
	}
	grantsCurrent := false
	for {
		open := strings.IndexByte(entries, '(')
		if open < 0 {
			if strings.Trim(entries, "PAIR") != "" {
				return errors.New("unsupported private file DACL flags")
			}
			break
		}
		if strings.Trim(entries[:open], "PAIR") != "" {
			return errors.New("unsupported private file DACL prefix")
		}
		end := strings.IndexByte(entries[open+1:], ')')
		if end < 0 {
			return errors.New("unterminated private file ACE")
		}
		end += open + 1
		parts := strings.Split(entries[open+1:end], ";")
		if len(parts) != 6 || parts[0] != "A" || parts[5] == "" {
			return errors.New("unsupported private file ACE")
		}
		if parts[3] != "" || parts[4] != "" {
			return errors.New("object-specific private file ACE is unsupported")
		}
		if parts[2] != "FA" && parts[2] != "GA" && parts[2] != "0x1f01ff" && parts[2] != "0x001f01ff" {
			return errors.New("private file ACE must grant full control")
		}
		trustee, err := windows.StringToSid(parts[5])
		if err != nil || trustee == nil || !trustee.IsValid() {
			return errors.New("private file ACE trustee SID is invalid")
		}
		if !trustee.Equals(current) && !trustee.Equals(system) && !trustee.Equals(admins) {
			return fmt.Errorf("private file DACL grants access to unauthorized SID %s", parts[5])
		}
		if trustee.Equals(current) && !strings.Contains(parts[1], "IO") {
			grantsCurrent = true
		}
		entries = entries[end+1:]
	}
	if !grantsCurrent {
		return errors.New("private file DACL does not grant full control to the current user")
	}
	return nil
}

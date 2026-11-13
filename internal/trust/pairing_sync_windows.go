//go:build windows

package trust

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// Windows metadata replacement uses MoveFileEx with WRITE_THROUGH. Only local
// NTFS volumes are supported; network/FAT/unknown volumes fail closed.
func syncPairingDirectory(dir string) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
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
		return errors.New("pairing state directory is a Windows reparse point")
	}
	var fs [32]uint16
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))); err != nil {
		return err
	}
	if !strings.EqualFold(windows.UTF16ToString(fs[:]), "NTFS") {
		return errors.New("pairing durability requires NTFS")
	}
	// NTFS may be served through SMB; checking only the filesystem name is
	// insufficient to establish local write-through persistence guarantees.
	var volumeRoot [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumePathName(name, &volumeRoot[0], uint32(len(volumeRoot))); err != nil {
		return fmt.Errorf("resolve pairing volume root: %w", err)
	}
	if driveType := windows.GetDriveType(&volumeRoot[0]); driveType != windows.DRIVE_FIXED {
		return fmt.Errorf("pairing durability requires a local fixed disk (type=%d)", driveType)
	}
	return nil
}

// Windows does not provide POSIX uid fields; validate effective ownership
// and DACL using the pathname's Windows security descriptor instead.
func pairingWindowsStateSecure(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	return secureWindowsPairingPath(path)
}

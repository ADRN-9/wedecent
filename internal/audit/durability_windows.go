//go:build windows

package audit

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// Windows exposes no portable directory fsync. Pairing audit persistence is
// therefore restricted to local fixed NTFS storage, alongside File.Sync.
// Physical power-loss validation remains a release gate.
func syncAuditDirectory(dir string) error {
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
		return errors.New("audit state directory is a reparse point")
	}
	var fs [32]uint16
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))); err != nil {
		return err
	}
	if !strings.EqualFold(windows.UTF16ToString(fs[:]), "NTFS") {
		return errors.New("audit persistence requires NTFS")
	}
	var volumeRoot [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumePathName(name, &volumeRoot[0], uint32(len(volumeRoot))); err != nil {
		return fmt.Errorf("resolve audit volume root: %w", err)
	}
	if typ := windows.GetDriveType(&volumeRoot[0]); typ != windows.DRIVE_FIXED {
		return fmt.Errorf("audit persistence requires a local fixed disk (type=%d)", typ)
	}
	return nil
}

func replaceAuditArchive(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

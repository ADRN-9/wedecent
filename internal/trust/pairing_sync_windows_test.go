//go:build windows

package trust

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPairingVolumeRejectsNonlocalAndRemovableDrives(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    uint32
		allowed bool
	}{
		{"fixed-local-volume", windows.DRIVE_FIXED, true},
		{"remote-smb-ntfs", windows.DRIVE_REMOTE, false},
		{"removable-storage", windows.DRIVE_REMOVABLE, false},
		{"ram-disk", windows.DRIVE_RAMDISK, false},
		{"unknown", windows.DRIVE_UNKNOWN, false},
		{"missing-root", windows.DRIVE_NO_ROOT_DIR, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowsPairingDriveTypeAllowed(tc.kind); got != tc.allowed {
				t.Fatalf("drive type %d permitted=%v, want %v", tc.kind, got, tc.allowed)
			}
		})
	}
}

func TestWindowsPairingLocalNTFSStatePreflight(t *testing.T) {
	preparePairingTestDir(t, t.TempDir())
	dir := t.TempDir()
	preparePairingTestDir(t, dir)
	if err := syncPairingDirectory(dir); err != nil {
		t.Fatalf("local native pairing metadata preflight: %v", err)
	}
}

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func setServeConfigTestACL(path, additionalACE string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)" + additionalACE,
	)
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
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner,
		nil,
		dacl,
		nil,
	)
}

func TestLoadServeConfigArgsWindowsACL(t *testing.T) {
	for _, tc := range []struct {
		name          string
		additionalACE string
		wantErr       bool
	}{
		{name: "private-owner-system-admins"},
		{name: "builtin-users-full-control", additionalACE: "(A;;FA;;;BU)", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent-config.json")
			if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := setServeConfigTestACL(path, tc.additionalACE); err != nil {
				t.Fatal(err)
			}
			_, err := loadServeConfigArgs(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("loadServeConfigArgs error=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

//go:build windows

package updateinfo

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateUpdateStateDACLFailClosed(t *testing.T) {
	const owner = "S-1-5-21-1234-5678-9012-1001"
	for _, tc := range []struct {
		name string
		sddl string
		valid bool
	}{
		{"private-user-system", "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)", true},
		{"world-access", "D:P(A;;FA;;;" + owner + ")(A;;FA;;;WD)", false},
		{"authenticated-users", "D:P(A;;FA;;;" + owner + ")(A;;FA;;;AU)", false},
		{"builtin-users", "D:P(A;;FA;;;" + owner + ")(A;;FA;;;BU)", false},
		{"partial-rights", "D:P(A;;FR;;;" + owner + ")", false},
		{"deny-ace", "D:P(D;;FA;;;WD)(A;;FA;;;" + owner + ")", false},
		{"missing-owner-grant", "D:P(A;;FA;;;SY)", false},
		{"inherit-only-owner", "D:P(A;IO;FA;;;" + owner + ")", false},
		{"malformed", "D:P(A;;FA;;;" + owner, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUpdateStateDACL(tc.sddl, owner, owner, false)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v, want valid=%v", err == nil, err, tc.valid)
			}
		})
	}
}

func TestValidateUpdateStateOwnerBoundary(t *testing.T) {
	const (
		user = "S-1-5-21-1234-5678-9012-1001"
		service = "S-1-5-21-1234-5678-9012-1002"
		other = "S-1-5-21-1234-5678-9012-1003"
	)
	for _, tc := range []struct {
		name string
		owner, current, root string
		admin, valid bool
	}{
		{"current-user", user, user, user, false, true},
		{"system", updateStateSystemSID, user, updateStateSystemSID, false, true},
		{"admin-owner", updateStateAdminSID, user, updateStateAdminSID, false, true},
		{"elevated-parent-owner", service, user, service, true, true},
		{"non-admin-foreign-owner", service, user, service, false, false},
		{"unrelated-owner", other, user, service, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUpdateStateOwner(tc.owner, tc.current, tc.root, tc.admin)
			if (err == nil) != tc.valid {
				t.Fatalf("error=%v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestWindowsUpdateStatePathRequiresPrivateOwnerAndDACL(t *testing.T) {
	dir := t.TempDir()
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStateDirInfo(dir, dirInfo); err != nil {
		t.Fatalf("private temp directory rejected: %v", err)
	}

	path := filepath.Join(dir, UpdateStateFilename)
	if err := os.WriteFile(path, []byte("{\"version\":1,\"stable_sequence\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStateFileInfo(path, fileInfo); err != nil {
		t.Fatalf("private update state file rejected: %v", err)
	}
}

func TestWindowsUpdateStateDACLUsesNativeSIDIdentity(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sddl := "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)"
	if err := validateUpdateStateDACL(sddl, sid, sid, false); err != nil {
		t.Fatalf("native current-user SID DACL rejected: %v", err)
	}
}

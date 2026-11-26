//go:build windows

package updateinfo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateUpdateStateDACLFailClosed(t *testing.T) {
	const owner = "S-1-5-21-1234-5678-9012-1001"
	for _, tc := range []struct {
		name  string
		sddl  string
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
		user    = "S-1-5-21-1234-5678-9012-1001"
		service = "S-1-5-21-1234-5678-9012-1002"
		other   = "S-1-5-21-1234-5678-9012-1003"
	)
	for _, tc := range []struct {
		name                 string
		owner, current, root string
		admin, valid         bool
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

func TestValidateUpdateStateAncestorDACLRejectsNamespaceWriters(t *testing.T) {
	const user = "S-1-5-21-1234-5678-9012-1001"
	for _, tc := range []struct {
		name    string
		sddl    string
		wantErr bool
	}{
		{"broad-principal-delete-child", "D:P(A;;FA;;;" + user + ")(A;;0x00000040;;;WD)", true},
		{"inherited-authenticated-users-create", "D:AI(A;CI;0x00000004;;;AU)(A;;FA;;;" + user + ")", true},
		{"inherited-world-write", "D:AI(A;OICI;0x00000002;;;WD)(A;;FA;;;" + user + ")", true},
		{"broad-principal-read-execute", "D:AI(A;OICI;FRFX;;;BU)(A;;FA;;;" + user + ")", false},
		{"trusted-system-admin-writers", "D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)(A;;FA;;;BA)", false},
		{"unknown-ace-type", "D:P(D;;0x00000040;;;WD)(A;;FA;;;" + user + ")", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUpdateStateAncestorDACL(tc.sddl, user)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateUpdateStateAncestorOwnerRejectsHostileOwner(t *testing.T) {
	const user = "S-1-5-21-1234-5678-9012-1001"
	for _, owner := range []string{
		"S-1-5-21-1234-5678-9012-1002",
		"S-1-5-11",
		"S-1-1-0",
	} {
		if err := validateUpdateStateAncestorOwner(owner, user); err == nil {
			t.Errorf("hostile ancestor owner %s was accepted", owner)
		}
	}
	for _, owner := range []string{user, updateStateSystemSID, updateStateAdminSID, updateStateTrustedInstallerSID} {
		if err := validateUpdateStateAncestorOwner(owner, user); err != nil {
			t.Errorf("trusted ancestor owner %s rejected: %v", owner, err)
		}
	}
}

func windowsTestCurrentSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("get current process SID: %v", err)
	}
	return user.User.Sid.String()
}

func windowsTestSetDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse test security descriptor: %v", err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("open directory to set test DACL: %v", err)
	}
	defer windows.CloseHandle(h)
	if err := windows.SetKernelObjectSecurity(h, windows.DACL_SECURITY_INFORMATION, sd); err != nil {
		t.Fatalf("set test DACL: %v", err)
	}
}

func TestWindowsUpdateStateRejectsHostileAncestorACL(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "writable-parent")
	stateDir := filepath.Join(parent, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	user := windowsTestCurrentSID(t)
	windowsTestSetDACL(t, parent, "D:P(A;;FA;;;"+user+")(A;;FA;;;SY)(A;;0x00000040;;;WD)")
	info, err := os.Lstat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStateDirInfo(stateDir, info); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("state directory under DELETE_CHILD-enabled parent accepted: %v", err)
	}
}

func TestWindowsUpdateStateRejectsInheritedBroadAncestorACE(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "inherited-parent")
	child := filepath.Join(parent, "state")
	grandchild := filepath.Join(child, "nested")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	user := windowsTestCurrentSID(t)
	windowsTestSetDACL(t, parent, "D:P(A;OICI;FA;;;"+user+")(A;OICI;0x00000004;;;WD)")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(grandchild, 0o700); err != nil {
		t.Fatal(err)
	}
	childSD, err := windows.GetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(childSD.String(), "WD") {
		t.Fatalf("test child did not inherit the broad-principal ACE: %s", childSD.String())
	}
	if _, err := validateUpdateStateAncestorChain(grandchild, user, false); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("inherited broad-principal write ACE accepted: %v", err)
	}
}

func TestWindowsUpdateStateRejectsHostileAncestorOwner(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "state-parent")
	stateDir := filepath.Join(parent, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	user := windowsTestCurrentSID(t)
	if err := validateUpdateStateAncestorOwner("S-1-5-21-9999-8888-7777-1001", user); err == nil {
		t.Fatal("untrusted parent owner was accepted")
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStateDirInfo(stateDir, info); err != nil {
		t.Fatalf("legitimate current-user-owned parent rejected: %v", err)
	}
}

func TestWindowsUpdateStateRejectsIntermediateReparseTraversal(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real-target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "redirect")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating a Windows directory symlink requires unavailable privilege: %v", err)
	}
	user := windowsTestCurrentSID(t)
	if _, err := validateUpdateStateAncestorChain(filepath.Join(link, "state"), user, false); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("intermediate reparse-point traversal accepted: %v", err)
	}
}

func TestWindowsUpdateStateAcceptsLegitimateNestedPath(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "WeDecent", "Updater", "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStateDirInfo(stateDir, info); err != nil {
		t.Fatalf("legitimate protected installation path rejected: %v", err)
	}
}

func TestWindowsUpdateStateRejectsNativeHostileAncestorOwner(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "foreign-owner")
	stateDir := filepath.Join(parent, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	user := windowsTestCurrentSID(t)
	sd, err := windows.SecurityDescriptorFromString("O:BUG:BAD:P(A;;FA;;;" + user + ")")
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(parent)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name,
		windows.READ_CONTROL|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("open parent to set test owner: %v", err)
	}
	defer windows.CloseHandle(h)
	if err := windows.SetKernelObjectSecurity(h, windows.OWNER_SECURITY_INFORMATION, sd); err != nil {
		t.Skipf("runner cannot assign an alternate directory owner: %v", err)
	}
	if _, err := validateUpdateStateAncestorChain(stateDir, user, false); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("directory with hostile native owner accepted: %v", err)
	}
}

func TestWindowsUpdateStateRejectsReparsePointSubstitution(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	stateDir := filepath.Join(parent, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	user := windowsTestCurrentSID(t)
	if err := validateStateDirAncestors(stateDir); err != nil {
		t.Fatalf("initial trusted ancestor validation failed: %v", err)
	}
	moved := filepath.Join(root, "moved-parent")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, parent); err != nil {
		t.Skipf("creating a Windows directory symlink requires unavailable privilege: %v", err)
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStateDirInfo(stateDir, info); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reparse-point substitution of a validated ancestor was accepted: %v", err)
	}
}

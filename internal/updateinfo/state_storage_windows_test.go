//go:build windows

package updateinfo

import (
	"context"
	"errors"
	"os"
	"os/exec"
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
		{"inherited-world-read-execute", "D:AI(A;;FA;;;" + owner + ")(A;OICI;FRFX;;;WD)", true},
		{"inherit-only-world-file-write", "D:AI(A;;FA;;;" + owner + ")(A;OIIO;GW;;;WD)", false},
		{"world-access", "D:P(A;;FA;;;" + owner + ")(A;;FA;;;WD)", false},
		{"world-generic-write", "D:P(A;;FA;;;" + owner + ")(A;;GW;;;WD)", false},
		{"world-add-subdirectory", "D:P(A;;FA;;;" + owner + ")(A;;0x00000004;;;WD)", false},
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
		{"broad-principal-write-ea", "D:P(A;;FA;;;" + user + ")(A;;0x00000010;;;WD)", true},
		{"broad-principal-generic-write-only", "D:P(A;;FA;;;" + user + ")(A;;GW;;;WD)", true},
		{"broad-principal-generic-all", "D:P(A;;FA;;;" + user + ")(A;;GA;;;WD)", true},
		{"inherited-authenticated-users-create-only", "D:AI(A;CI;0x00000004;;;AU)(A;;FA;;;" + user + ")", false},
		{"inherited-world-create-file-only", "D:AI(A;OICI;0x00000002;;;WD)(A;;FA;;;" + user + ")", false},
		{"inherit-only-world-generic-write-is-not-effective-on-parent", "D:AI(A;OICIIO;GW;;;WD)(A;;FA;;;" + user + ")", false},
		{"inherit-only-object-write-does-not-modify-directory", "D:AI(A;OIIO;GW;;;WD)(A;;FA;;;" + user + ")", false},
		{"broad-principal-read-execute", "D:AI(A;OICI;FRFX;;;BU)(A;;FA;;;" + user + ")", false},
		{"list-children-create-only-mask", "D:AI(A;;LC;;;BU)(A;;FA;;;" + user + ")", false},
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
	if err := validateUpdateStateDACL(childSD.String(), user, user, false); err == nil {
		t.Fatalf("inherited broad-principal write ACE on state object accepted: DACL=%s", childSD.String())
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

func TestWindowsUpdateStatePreflightRejectsHostileParentBeforeCreate(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "hostile")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	user := windowsTestCurrentSID(t)
	windowsTestSetDACL(t, parent, "D:P(A;;FA;;;"+user+")(A;;0x00000040;;;WD)")
	stateDir := filepath.Join(parent, "new", "state")
	if err := ensurePrivateStateDir(stateDir); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("state directory creation under hostile ancestor accepted: %v", err)
	}
	if _, err := os.Lstat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe state directory was created before ACL rejection: %v", err)
	}
}

func TestWindowsStateStoreRejectsAncestorACLBeforeReadOrAdvance(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "hostile")
	stateDir := filepath.Join(parent, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := StatePath(stateDir)
	original := []byte("{\"version\":1,\"stable_sequence\":41}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	user := windowsTestCurrentSID(t)
	windowsTestSetDACL(t, parent, "D:P(A;;FA;;;"+user+")(A;;FA;;;SY)(A;;0x00000040;;;WD)")
	store := NewStateStore(path)
	if _, err := store.Load(); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Load accepted state below hostile parent: %v", err)
	}
	if err := store.Advance(42); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Advance accepted state below hostile parent: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("failed ACL validation changed rollback state: %q", got)
	}

	missingDir := filepath.Join(parent, "missing-state")
	missingStore := NewStateStore(StatePath(missingDir))
	if _, err := missingStore.Load(); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Load accepted missing state below hostile ancestor: %v", err)
	}
	if err := missingStore.Advance(43); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Advance accepted missing state below hostile ancestor: %v", err)
	}
	if _, err := os.Lstat(missingDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe missing-state directory was created: %v", err)
	}
}

func windowsTestCreateJunction(t *testing.T, link, target string) {
	t.Helper()
	output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Skipf("creating a Windows junction is unavailable: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

func TestWindowsUpdateStateRejectsJunctionTraversalAndSubstitution(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real-target")
	if err := os.MkdirAll(filepath.Join(target, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	user := windowsTestCurrentSID(t)

	link := filepath.Join(root, "junction")
	windowsTestCreateJunction(t, link, target)
	if _, err := validateUpdateStateAncestorChain(filepath.Join(link, "state"), user, false); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("junction traversal accepted: %v", err)
	}

	parent := filepath.Join(root, "parent")
	stateDir := filepath.Join(parent, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateStateDirAncestors(stateDir); err != nil {
		t.Fatalf("initial ancestor validation failed: %v", err)
	}
	moved := filepath.Join(root, "moved-parent")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.MkdirAll(filepath.Join(replacement, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	windowsTestCreateJunction(t, parent, replacement)
	info, err := os.Lstat(filepath.Join(parent, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStateDirInfo(filepath.Join(parent, "state"), info); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("junction substituted for a previously validated ancestor was accepted: %v", err)
	}
}

func TestWindowsUpdateStateRejectsInheritedFileWritePermissions(t *testing.T) {
	user := windowsTestCurrentSID(t)
	for _, tc := range []struct {
		name string
		mask string
	}{
		{"write-data", "0x00000002"},
		{"append-data", "0x00000004"},
		{"write-extended-attributes", "0x00000010"},
		{"delete-child-namespace", "0x00000040"},
		{"write-attributes", "0x00000100"},
		{"delete", "0x00010000"},
		{"write-dac", "0x00040000"},
		{"write-owner", "0x00080000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			// OI-only makes this ACE apply to files, not as an effective
			// permission on the containing directory. Keep an inheritable
			// owner ACE so the native test can inspect the created file.
			windowsTestSetDACL(t, dir, "D:P(A;;FA;;;"+user+")(A;OI;FA;;;"+user+")(A;OI;"+tc.mask+";;;WD)")
			dirSD, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("actual updater-state directory DACL: %s", dirSD.String())
			path := StatePath(dir)
			if err := os.WriteFile(path, []byte("{\"version\":1,\"stable_sequence\":41}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			sddl := sd.String()
			t.Logf("actual updater-state file DACL: %s", sddl)
			if !strings.Contains(sddl, "WD") && !strings.Contains(sddl, "S-1-1-0") {
				t.Fatalf("state file did not inherit broad-principal ACE; actual file DACL: %s", sddl)
			}
			if err := validateUpdateStateDACL(sddl, user, user, false); err == nil {
				t.Fatalf("state file accepted inherited write/namespace mask %s; actual file DACL: %s", tc.mask, sddl)
			}
		})
	}
}

func TestWindowsStateStoreRejectsInheritedFileACLBeforeIOAndLock(t *testing.T) {
	user := windowsTestCurrentSID(t)
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The append-data mask is inherited by files only. This must be rejected
	// during directory preflight, before state reads, temp files, or lock files.
	windowsTestSetDACL(t, dir, "D:P(A;;FA;;;"+user+")(A;OI;FA;;;"+user+")(A;OI;0x00000004;;;WD)")
	dirSD, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dirDACL := dirSD.String()
	t.Logf("actual updater-state directory DACL before state operations: %s", dirDACL)
	if !strings.Contains(dirDACL, "WD") && !strings.Contains(dirDACL, "S-1-1-0") {
		t.Fatalf("updater-state directory did not retain the inherited broad-principal ACE: %s", dirDACL)
	}
	path := StatePath(dir)
	original := []byte("{\"version\":1,\"stable_sequence\":41}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	fileSD, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual updater-state file DACL before state operations: %s", fileSD.String())
	if err := validateUpdateStateDACL(fileSD.String(), user, user, false); err == nil {
		t.Fatalf("actual inherited state-file DACL accepted: %s", fileSD.String())
	}
	store := NewStateStore(path)
	if _, err := store.Load(); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Load accepted state with inherited file append permission: %v", err)
	}
	if err := store.Advance(42); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Advance accepted state with inherited file append permission: %v", err)
	}
	if err := saveState(path, State{Version: UpdateStateVersion, StableSequence: 42}); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("saveState created a temporary file under inherited file append permission: %v", err)
	}
	if _, err := acquireUpdateLock(context.Background(), path); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("update lock acquisition accepted inherited file append permission: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("rejected state operations changed rollback bytes: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".update-apply.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe update lock was created: %v", err)
	}
	temps, err := filepath.Glob(filepath.Join(dir, ".update-state-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("unsafe temporary state files were created: %v", temps)
	}
}

func windowsTestSetFileDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse test file security descriptor: %v", err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("open state file to set test DACL: %v", err)
	}
	defer windows.CloseHandle(h)
	if err := windows.SetKernelObjectSecurity(h, windows.DACL_SECURITY_INFORMATION, sd); err != nil {
		t.Fatalf("set state file DACL: %v", err)
	}
}

func TestWindowsStateStoreRejectsHostileStateFileACLBeforeReadOrAdvance(t *testing.T) {
	user := windowsTestCurrentSID(t)
	dir := t.TempDir()
	path := StatePath(dir)
	original := []byte("{\"version\":1,\"stable_sequence\":41}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	windowsTestSetFileDACL(t, path, "D:P(A;;FA;;;"+user+")(A;;0x00000004;;;WD)")
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	t.Logf("actual updater-state file DACL with explicit broad append-data ACE: %s", sddl)
	if err := validateUpdateStateDACL(sddl, user, user, false); err == nil {
		t.Fatalf("state-file validator accepted broad append-data ACE: %s", sddl)
	}
	store := NewStateStore(path)
	if _, err := store.Load(); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Load accepted state file with broad append-data permission: %v", err)
	}
	if err := store.Advance(42); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Advance accepted state file with broad append-data permission: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("rejected state-file ACL changed rollback bytes: %q", got)
	}
	temps, err := filepath.Glob(filepath.Join(dir, ".update-state-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("Advance created temporary state files after rejecting the state-file ACL: %v", temps)
	}
}

func TestWindowsUpdateLockRejectsHostileLockFileACLBeforeLocking(t *testing.T) {
	user := windowsTestCurrentSID(t)
	dir := t.TempDir()
	statePath := StatePath(dir)
	lockPath := filepath.Join(dir, ".update-apply.lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	windowsTestSetFileDACL(t, lockPath, "D:P(A;;FA;;;"+user+")(A;;0x00000004;;;WD)")
	sd, err := windows.GetNamedSecurityInfo(lockPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual updater lock-file DACL with broad append-data ACE: %s", sd.String())
	if _, err := acquireUpdateLock(context.Background(), statePath); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("update lock acquisition accepted hostile lock-file ACL: %v", err)
	}

	file, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		t.Fatalf("rejected updater retained the lock after ACL failure: %v", err)
	}
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped); err != nil {
		t.Fatalf("release test lock: %v", err)
	}
}


// A writable hostile sibling may be created under a parent that permits
// additive child creation. If it is later substituted at the protected state
// name, the state store must reject its DACL before reading or changing data.
func TestWindowsUpdateStateRejectsHostileSiblingSubstitution(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	sibling := filepath.Join(root, "sibling")
	displaced := filepath.Join(root, "displaced-state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("{\"version\":1,\"stable_sequence\":41}\\n")
	statePath := StatePath(stateDir)
	if err := os.WriteFile(statePath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	hostilePath := StatePath(sibling)
	hostile := []byte("{\"version\":1,\"stable_sequence\":999}\\n")
	if err := os.WriteFile(hostilePath, hostile, 0o600); err != nil {
		t.Fatal(err)
	}

	user := windowsTestCurrentSID(t)
	windowsTestSetDACL(t, sibling,
		"D:P(A;OICI;FA;;;"+user+")(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)")

	if _, err := NewStateStore(statePath).Load(); err != nil {
		t.Fatalf("trusted original state was rejected before substitution: %v", err)
	}
	if err := os.Rename(stateDir, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(sibling, stateDir); err != nil {
		t.Fatalf("substitute hostile sibling at protected state path: %v", err)
	}

	if _, err := NewStateStore(statePath).Load(); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("hostile sibling substituted at state path was accepted: %v", err)
	}
	gotOriginal, err := os.ReadFile(StatePath(displaced))
	if err != nil || string(gotOriginal) != string(original) {
		t.Fatalf("original state changed during hostile sibling rejection: %q: %v", gotOriginal, err)
	}
	gotHostile, err := os.ReadFile(StatePath(stateDir))
	if err != nil || string(gotHostile) != string(hostile) {
		t.Fatalf("hostile sibling contents changed during rejection: %q: %v", gotHostile, err)
	}
}

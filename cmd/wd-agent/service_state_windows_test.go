//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"strconv"
	"testing"

	"golang.org/x/sys/windows"
	"wedecent.com/wedecent/internal/trust"
	"wedecent.com/wedecent/internal/winservice"
)

func TestServiceStartupRejectsBroadStateBeforeLogOrIdentity(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, true)
	if _, err := openServiceLog(dir); err == nil {
		t.Fatal("service log opened before refusing broad state DACL")
	}
	if err := verifyWindowsServiceState(dir); err == nil {
		t.Fatal("service startup accepted broad inherited or explicit ACL")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unsafe state was modified: %v, %v", entries, err)
	}
}

func TestServiceStartupRejectsForeignOwnerBeforeLog(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, false)
	wrong, err := windows.StringToSid("S-1-5-20")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsStateForSID(dir, wrong); err == nil {
		t.Fatal("directory owned by current token accepted as foreign service SID")
	}
	if _, err := os.Lstat(filepath.Join(dir, "service.log")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign service check modified log state: %v", err)
	}
}

func TestServiceLogOpenRejectsRedirectedFile(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, false)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "service.log")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	if _, err := openServiceLog(dir); err == nil {
		t.Fatal("service log followed redirected file")
	}
	b, err := os.ReadFile(outside)
	if err != nil || string(b) != "unchanged" {
		t.Fatalf("redirected log target changed: %q: %v", b, err)
	}
}

func TestServiceLogSecureFirstOpenAndReopen(t *testing.T) {
	// Preflight's native CreateDirectory security attributes establish the
	// actual account SID as owner (TempDir may be group-owned on CI).
	dir := filepath.Join(t.TempDir(), "service-owned")
	if err := preflightAgentState(dir); err != nil {
		t.Fatal(err)
	}
	hold, err := guardWindowsServiceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	for i := 0; i < 2; i++ {
		f, err := openServiceLog(dir)
		if err != nil {
			t.Fatalf("protected service log open %d: %v", i, err)
		}
		if _, err := f.WriteString("authorized diagnostic\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if err := trust.VerifyPairingStatePath(filepath.Join(dir, "service.log")); err != nil {
			t.Fatalf("service log ACL unexpectedly broad: %v", err)
		}
	}
}

func TestServiceStartupRejectsAmbiguousAndReparseAncestors(t *testing.T) {
	for _, path := range []string{`\\server\share\state`, `C:\state\..\agent`, `C:\bad:stream`} {
		if _, err := guardWindowsServiceState(path); err == nil {
			t.Fatalf("unsafe service state path accepted: %q", path)
		}
	}
}

func TestServiceProvisionRefusesExistingMaterialBeforeACLMutation(t *testing.T) {
	// A distinct real SID requires a controlled elevated integration fixture.
	// Here the injected test SID is deliberately nonexistent; it must fail
	// before mkdir, chmod or any identity write.
	dir := filepath.Join(t.TempDir(), "service-state")
	err := provisionWindowsServiceState(dir, "WEDECENT-MISSING-SERVICE-ACCOUNT-0001")
	if err == nil {
		t.Fatal("nonexistent service account accepted")
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid account mutated state: %v", err)
	}
}

func TestServiceProvisionDistinctConfiguredSIDNativeIntegration(t *testing.T) {
	account := strings.TrimSpace(os.Getenv("WEDECENT_TEST_SERVICE_ACCOUNT"))
	if account == "" {
		t.Skip("requires an elevated Windows environment with a distinct dedicated service account")
	}
	adminSID, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	isAdmin, err := windows.GetCurrentProcessToken().IsMember(adminSID)
	if err != nil || !isAdmin {
		t.Skip("native account owner changes require elevated installer privileges")
	}
	configured, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if configured.User.Sid == nil {
		t.Fatal("installer SID missing")
	}
	serviceSID, err := winservice.ResolveServiceAccountSID(account)
	if err != nil {
		t.Fatal(err)
	}
	if serviceSID.Equals(configured.User.Sid) {
		t.Fatal("same-user fixture does not prove distinct service identity")
	}
	// A service state parent must itself have a protected DACL; broad
	// ancestors are rejected rather than relying on open-handle rename behavior.
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" {
		t.Fatal("ProgramData is required for a machine-wide service-state fixture")
	}
	parent := filepath.Join(programData, "WeDecent-C232-" + strconv.Itoa(os.Getpid()))
	if _, err := os.Lstat(parent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("service-state fixture path already exists: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	admins, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightWindowsAgentState(parent, windowsStateProvisionHooks{ownerSID: admins}); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(parent, "dedicated-service-state")
	if err := provisionWindowsServiceState(state, account); err != nil {
		t.Fatalf("distinct service SID preflight/provision failed: %v", err)
	}
	owner, err := windowsServiceOwner(state)
	if err != nil || !owner.Equals(serviceSID) {
		t.Fatalf("wrong dedicated service state owner %v: %v", owner, err)
	}
	if err := trust.VerifyPairingStatePath(state); err != nil {
		t.Fatalf("service state retained inherited unauthorized ACE: %v", err)
	}
	t.Logf("provisioned protected empty service state under distinct service SID %s", serviceSID)
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatalf("sensitive material created during installer provisioning: %v, %v", entries, err)
	}
	// The caller MUST subsequently test SCM startup and DPAPI persistence
	// under this exact different account. No same-user fixture substitutes.
}

func TestServiceRuntimeGuardRejectsObservedPathSubstitution(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "service-owned")
	if err := preflightAgentState(dir); err != nil {
		t.Fatal(err)
	}
	unlock, err := guardWindowsServiceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	swapped := dir + "-swapped"
	if err := os.Rename(dir, swapped); err == nil {
		// On some Windows volumes a rename may succeed despite our guard.
		// No subsequent service state write may follow the absent old path.
		if err := verifyWindowsServiceState(dir); err == nil {
			t.Fatal("state substitution was not detected")
		}
		if _, err := openServiceLog(dir); err == nil {
			t.Fatal("log was created after state pathname substitution")
		}
		if err := os.Rename(swapped, dir); err != nil {
			t.Fatalf("restore renamed test fixture: %v", err)
		}
	} else {
		t.Logf("directory rename prevented by open state handles: %v", err)
	}
	if err := verifyWindowsServiceState(dir); err != nil {
		t.Fatalf("restored state unexpectedly invalid: %v", err)
	}
}

func TestServiceProvisionRejectsExistingSensitiveFilesWithoutRepair(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, false)
	key := filepath.Join(dir, "identity.key.dpapi")
	content := []byte("existing-key-must-not-be-rewritten")
	if err := os.WriteFile(key, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireEmptyWindowsServiceState(dir); err == nil {
		t.Fatal("existing sensitive service state was silently accepted")
	}
	read, err := os.ReadFile(key)
	if err != nil || string(read) != string(content) {
		t.Fatalf("existing identity material changed: %q, %v", read, err)
	}
}

func TestServiceStartupLocksPathBeforeRejectingBroadACL(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, true)
	if _, err := os.Lstat(filepath.Join(dir, "service.log")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("test fixture unexpectedly contains service log: %v", err)
	}
	err := runServiceRun([]string{
		"--state=" + dir,
		"--name=acl-order-test",
		"--listen=",
		"--web-relay=",
	})
	if err == nil || !strings.Contains(err.Error(), "verify guarded service state") {
		t.Fatalf("service startup did not reject broad ACL under path guard: %v", err)
	}
	for _, name := range []string{"service.log", "identity.key.dpapi", "identity.crt"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("service created %s before guarded ACL verification: %v", name, err)
		}
	}
}

func TestServiceRuntimeGuardDetectsStateAndAncestorSubstitution(t *testing.T) {
	root := filepath.Join(t.TempDir(), "protected-root")
	state := filepath.Join(root, "agent")
	if err := preflightAgentState(state); err != nil {
		t.Fatal(err)
	}
	if err := trust.VerifyPairingStatePath(root); err != nil {
		t.Fatalf("newly created service-state parent is not protected: %v", err)
	}
	release, err := guardWindowsServiceState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	// Windows permits the directory owner to rename an open directory.
	// The guard is not an ACL substitute; path verification must fail closed
	// before a log or sensitive file can be created at the old pathname.
	swappedState := state + "-renamed"
	if err := os.Rename(state, swappedState); err != nil {
		t.Fatalf("same-owner rename fixture: %v", err)
	}
	if err := verifyWindowsServiceState(state); err == nil {
		t.Fatal("renamed state path remained trusted")
	}
	if _, err := openServiceLog(state); err == nil {
		t.Fatal("service log opened through the substituted state pathname")
	}
	if err := os.Rename(swappedState, state); err != nil {
		t.Fatalf("restore renamed state fixture: %v", err)
	}

	swappedRoot := root + "-renamed"
	if err := os.Rename(root, swappedRoot); err == nil {
		t.Fatal("guarded ancestor directory was renamed while its parent handle was held")
	} else if !os.IsPermission(err) {
		t.Fatalf("ancestor rename failed for an unexpected reason: %v", err)
	}
	if err := verifyWindowsServiceState(state); err != nil {
		t.Fatalf("protected ancestor path unexpectedly changed: %v", err)
	}
}

func TestServiceProvisionRejectsBroadExistingParentDACL(t *testing.T) {
	broadParent := prepareWindowsPreflightTestDir(t, true)
	if err := verifyWindowsServiceStateParent(filepath.Join(broadParent, "agent")); err == nil {
		t.Fatal("service provisioning accepted an existing parent with broad access")
	}
	privateParent := prepareWindowsPreflightTestDir(t, false)
	if err := verifyWindowsServiceStateParent(filepath.Join(privateParent, "agent")); err != nil {
		t.Fatalf("service provisioning rejected a protected parent: %v", err)
	}
}
func TestServiceStartupRejectsForeignAncestorOwnerBeforeLogIdentityOrRecoveryLoad(t *testing.T) {
	root := filepath.Join(t.TempDir(), "protected-root")
	state := filepath.Join(root, "agent")
	if err := preflightAgentState(state); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(state, "recovery-authority.token")
	trustPath := filepath.Join(state, "recovery-authority-trust.json")
	tokenSentinel := []byte("sentinel-token-must-not-be-loaded")
	trustSentinel := []byte("sentinel-trust-must-not-be-loaded")
	if err := os.WriteFile(tokenPath, tokenSentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, trustSentinel, 0o600); err != nil {
		t.Fatal(err)
	}
	foreign, err := windows.StringToSid("S-1-5-20")
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, foreign, nil, nil, nil); err != nil {
		t.Skipf("hostile ancestor owner fixture requires owner reassignment privilege: %v", err)
	}

	// Exercise the real service startup entry point, not only the helper.
	err = runServiceRun([]string{
		"--state=" + state,
		"--name=hostile-owner-startup",
		"--listen=",
		"--web-relay=",
	})
	if err == nil || !strings.Contains(err.Error(), "verify guarded service state before loading recovery credentials") {
		t.Fatalf("service startup did not reject hostile ancestor owner before recovery loading: %v", err)
	}
	for _, name := range []string{"service.log", "identity.key.dpapi", "identity.crt"} {
		if _, statErr := os.Lstat(filepath.Join(state, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("service created %s before rejecting hostile ancestor owner: %v", name, statErr)
		}
	}
	gotToken, err := os.ReadFile(tokenPath)
	if err != nil || string(gotToken) != string(tokenSentinel) {
		t.Fatalf("recovery bearer was changed or consumed before owner rejection: %q: %v", gotToken, err)
	}
	gotTrust, err := os.ReadFile(trustPath)
	if err != nil || string(gotTrust) != string(trustSentinel) {
		t.Fatalf("recovery trust was changed before owner rejection: %q: %v", gotTrust, err)
	}
}

func TestServiceStartupRejectsUntrustedAncestorDeleteChild(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "protected-parent")
	if err := preflightAgentState(parent); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(parent, "agent")
	if err := preflightAgentState(state); err != nil {
		t.Fatal(err)
	}
	active, err := activeWindowsSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + active.String() + ")(A;;0x00000040;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("construct hostile ancestor DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsStateForSID(state, active); err == nil || !strings.Contains(err.Error(), "ancestor grants pathname mutation rights") {
		t.Fatalf("untrusted FILE_DELETE_CHILD permission was not rejected: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(state, "service.log")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ancestor ACL rejection created service log: %v", err)
	}
}

func TestServiceStartupFailsClosedBeforeSensitiveStateOnAncestorMutationACL(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "protected-parent")
	if err := preflightAgentState(parent); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(parent, "agent")
	if err := preflightAgentState(state); err != nil {
		t.Fatal(err)
	}
	active, err := activeWindowsSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + active.String() + ")(A;;0x00000040;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("construct hostile ancestor DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	err = runServiceRun([]string{"--state=" + state, "--name=ancestor-acl-test", "--listen=", "--web-relay="})
	if err == nil || !strings.Contains(err.Error(), "verify guarded service state") {
		t.Fatalf("service startup did not reject hostile ancestor ACL: %v", err)
	}
	for _, name := range []string{"service.log", "identity.key.dpapi", "identity.crt"} {
		if _, err := os.Lstat(filepath.Join(state, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("service created %s after ancestor ACL rejection: %v", name, err)
		}
	}
}

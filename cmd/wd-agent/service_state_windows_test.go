//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"wedecent.com/wedecent/internal/trust"
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
	dir := prepareWindowsPreflightTestDir(t, false)
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
		t.Skip("requires controlled VM with a distinct dedicated service account and elevated installer")
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
	state := filepath.Join(t.TempDir(), "dedicated-service-state")
	if err := provisionWindowsServiceState(state, account); err != nil {
		t.Fatalf("distinct service SID preflight/provision failed: %v", err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatalf("sensitive material created during installer provisioning: %v, %v", entries, err)
	}
	// The caller MUST subsequently test SCM startup and DPAPI persistence
	// under this exact different account. No same-user fixture substitutes.
}

func TestServiceRuntimeGuardBlocksRename(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, false)
	unlock, err := guardWindowsServiceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := os.Rename(dir, dir+"-swapped"); err == nil {
		t.Fatal("state root renamed while no-delete-sharing handle held")
	}
	if err := verifyWindowsServiceState(dir); err != nil {
		t.Fatalf("guarded state unexpectedly corrupted: %v", err)
	}
}

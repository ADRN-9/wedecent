//go:build windows

package main

import (
	"context"
	"fmt"
	"os/exec"
	"sync"

	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"wedecent.com/wedecent/internal/trust"

	"golang.org/x/sys/windows"
)

func prepareWindowsPreflightTestDir(t *testing.T, broad bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if broad {
		sddl += "(A;OICI;FA;;;BU)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAgentStatePreflightAllowsPrivateWindowsDirectory(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, false)
	if err := preflightAgentState(dir); err != nil {
		t.Fatalf("private agent state unexpectedly rejected: %v", err)
	}
}

func TestAgentStatePreflightRejectsBroadACLBeforeIdentityWrites(t *testing.T) {
	dir := prepareWindowsPreflightTestDir(t, true)
	for name, run := range map[string]func() error{
		"init": func() error {
			return runInit([]string{"--state", dir, "--name", "acl-test"})
		},
		"pairing-secret": func() error {
			return runPairingSecret([]string{"--state", dir})
		},
		"clients-list": func() error {
			return runClientsList([]string{"--state", dir})
		},
		"clients-revoke": func() error {
			return runClientsRevoke([]string{"--state", dir, "wd_aaaaaaaaaaaaaaaa"})
		},
		"identity": func() error {
			return runIdentity([]string{"--state", dir, "--name", "acl-test"})
		},
		"enrollment-proof": func() error {
			return runEnrollmentProof([]string{"--state", dir, "--request"})
		},
		"serve": func() error {
			return runAgent(context.Background(), serveConfig{StateDir: dir, Name: "acl-test"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil || !strings.Contains(err.Error(), "agent state security preflight") {
				t.Fatalf("insecure state not rejected before identity operations: %v", err)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("state created files before ACL validation: %v", entries)
			}
			for _, file := range []string{"identity.key.dpapi", "identity.key", "identity.crt", "pairing-secret.sha256", "trusted-clients.json"} {
				_, statErr := os.Lstat(filepath.Join(dir, file))
				if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("%s created before ACL rejection: %v", file, statErr)
				}
			}
		})
	}
}

func TestWindowsAgentStateFirstRunProtectedDespiteBroadParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "broad-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "D:P(A;OICI;FA;;;" + user.User.Sid.String() +
		")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("invalid parent DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(parent, ".wedecent", "agent")
	if err := preflightAgentState(state); err != nil {
		t.Fatalf("protected first-run creation rejected: %v", err)
	}
	if err := trust.VerifyPairingStatePath(state); err != nil {
		t.Fatalf("new state inherited unauthorized access: %v", err)
	}
	after, err := windows.GetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || before.String() != after.String() {
		t.Fatalf("preflight modified existing parent permissions: %v", err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatalf("preflight wrote secret material before state verification: %v, %v", entries, err)
	}
	if err := runInit([]string{"--state", state, "--name", "new-private-agent"}); err != nil {
		t.Fatalf("identity and pairing creation failed after preflight: %v", err)
	}
	for _, name := range []string{"identity.crt", "pairing-secret.sha256"} {
		if err := trust.VerifyPairingStatePath(filepath.Join(state, name)); err != nil {
			t.Fatalf("new %s not securely protected: %v", name, err)
		}
	}
}

func TestWindowsAgentStateConcurrentFirstRun(t *testing.T) {
	state := filepath.Join(t.TempDir(), ".wedecent", "agent")
	const workers = 24
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- preflightAgentState(state)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent private initialization failed: %v", err)
		}
	}
	if err := trust.VerifyPairingStatePath(state); err != nil {
		t.Fatalf("concurrent initialization created insecure state: %v", err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatalf("concurrent preflight wrote identity/pairing material: %v, %v", entries, err)
	}
}

func TestWindowsAgentStateProvisionFailureCleansOnlyNewDirectories(t *testing.T) {
	parent := t.TempDir()
	state := filepath.Join(parent, "private-root", "agent")
	fault := errors.New("injected post-create failure")
	err := preflightWindowsAgentState(state, windowsStateProvisionHooks{
		afterCreate: func(path string) error {
			if path == state {
				return fault
			}
			return nil
		},
	})
	if !errors.Is(err, fault) {
		t.Fatalf("injected provisioning failure was ignored: %v", err)
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed first-run directory retained unexpectedly: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(parent, "private-root")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty newly created ancestor retained unexpectedly: %v", err)
	}
	if _, err := os.Stat(parent); err != nil {
		t.Fatalf("existing parent changed during cleanup: %v", err)
	}
	if err := preflightAgentState(state); err != nil {
		t.Fatalf("fresh initialization failed after cleanup: %v", err)
	}
}

func TestWindowsAgentStateRejectsAmbiguousPaths(t *testing.T) {
	for _, path := range []string{
		"relative\\agent",
		`\\server\share\agent`,
		`C:\agent\..\state`,
		`C:\agent\.`,
		`C:\state:stream`,
		`C:\CON\agent`,
	} {
		t.Run(fmt.Sprintf("%q", path), func(t *testing.T) {
			if err := preflightAgentState(path); err == nil {
				t.Fatal("ambiguous or unsupported agent state path accepted")
			}
		})
	}
}

func TestWindowsAgentStateRejectsReparseAncestor(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "redirect")
	cmd := exec.Command("cmd", "/c", "mklink", "/J", junction, target)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("junction provisioning unavailable: %v (%s)", err, output)
	}
	if err := preflightAgentState(filepath.Join(junction, "agent")); err == nil {
		t.Fatal("Windows junction ancestor was accepted")
	}
	if _, err := os.Lstat(filepath.Join(target, "agent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reparse target was modified: %v", err)
	}
}

func TestWindowsAgentStateRejectsForeignOwner(t *testing.T) {
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := windows.StringToSid("S-1-5-20") // Network Service
	if err != nil {
		t.Fatal(err)
	}
	if windowsAgentStateOwnerAllowed(foreign, self.User.Sid) {
		t.Fatal("unrelated Windows SID was accepted")
	}
	if !windowsAgentStateOwnerAllowed(self.User.Sid, self.User.Sid) {
		t.Fatal("active dedicated service-account SID was rejected")
	}
	state := prepareWindowsPreflightTestDir(t, false)
	if err := windows.SetNamedSecurityInfo(state, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, foreign, nil, nil, nil); err != nil {
		t.Skipf("native owner reassignment requires elevated privileges: %v", err)
	}
	if err := preflightAgentState(state); err == nil {
		t.Fatal("foreign-owned existing state directory accepted")
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatalf("foreign-owned state was modified: %v, %v", entries, err)
	}
}

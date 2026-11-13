//go:build windows

package trust

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// Test fixtures must not inherit GitHub runner / system temporary-directory
// ACLs. Tests explicitly exercise strict production-style state permissions.
func preparePairingTestDir(t *testing.T, dir string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	cmd := exec.Command("icacls.exe", dir, "/inheritance:r", "/grant:r",
		"*"+sid+":(OI)(CI)F",
		"*S-1-5-18:(OI)(CI)F",
		"*S-1-5-32-544:(OI)(CI)F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("provision pairing test state: %v: %s", err, output)
	}
	if err := secureWindowsPairingPath(dir); err != nil {
		t.Fatalf("provisioned pairing test state is unsafe: %v", err)
	}
}

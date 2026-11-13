//go:build windows

package session

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func preparePairingSessionTestDir(t *testing.T, dir string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	output, err := exec.Command("icacls.exe", dir, "/inheritance:r", "/grant:r",
		"*"+sid+":(OI)(CI)F",
		"*S-1-5-18:(OI)(CI)F",
		"*S-1-5-32-544:(OI)(CI)F").CombinedOutput()
	if err != nil {
		t.Fatalf("prepare private pairing test state: %v: %s", err, output)
	}
}

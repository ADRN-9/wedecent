//go:build windows

package audit

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func secureRecoveryTestDir(t *testing.T, dir string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("private recovery fixture DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPairingRecoveryRejectsWorldTrusteeOnWindows(t *testing.T) {
	dir := recoveryTestDir(t)
	r, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Begin(testRecoveryRecord(strings.Repeat("f", 32))); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatal("invalid world-access test DACL")
	}
	if err := windows.SetNamedSecurityInfo(filepath.Join(dir, PairingOutcomeFileName),
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Skipf("Windows file ACL manipulation unavailable: %v", err)
	}
	if _, err := OpenPairingRecovery(dir); err == nil {
		t.Fatal("recovery file with world ACE was accepted")
	}
}

//go:build windows

package audit

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
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


func setRecoveryAuthorityTrustTestACL(path, additionalACE string) error {
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

func recoveryAuthorityTrustFixtureJSON() []byte {
	key := func(value byte) string {
		return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
	}
	return []byte(fmt.Sprintf(
		`{"primary_key":%q,"witnesses":{"one":%q,"two":%q,"three":%q},"quorum":2}\n`,
		key(1), key(2), key(3), key(4),
	))
}

func TestLoadRecoveryAuthorityTrustRejectsUnsafeWindowsDACL(t *testing.T) {
	dir := t.TempDir()
	secureRecoveryTestDir(t, dir)
	path := filepath.Join(dir, "recovery-authority-trust.json")
	if err := os.WriteFile(path, recoveryAuthorityTrustFixtureJSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setRecoveryAuthorityTrustTestACL(path, ""); err != nil {
		t.Fatalf("set private trust-file DACL: %v", err)
	}
	if _, err := LoadRecoveryAuthorityTrust(path); err != nil {
		t.Fatalf("private trust-file DACL rejected: %v", err)
	}

	if err := setRecoveryAuthorityTrustTestACL(path, "(A;;FA;;;BU)"); err != nil {
		t.Fatalf("set unsafe trust-file DACL: %v", err)
	}
	if _, err := LoadRecoveryAuthorityTrust(path); err == nil {
		t.Fatal("LoadRecoveryAuthorityTrust accepted a trust file writable by BUILTIN\\Users")
	}
}

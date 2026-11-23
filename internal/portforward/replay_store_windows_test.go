//go:build windows

package portforward

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func setReplayTestFileACL(path, additionalACE string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid
	sddl := fmt.Sprintf("O:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)%s", sid.String(), sid.String(), additionalACE)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
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

func TestWindowsReplayRejectsUnauthorizedDirectoryACL(t *testing.T) {
	dir := newReplayTestDir(t)
	if err := setReplayTestFileACL(dir, "(A;OICI;FA;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if err := secureReplayDirectory(dir); err == nil {
		t.Fatal("replay directory with BUILTIN\\Users access was accepted")
	}
}

func TestWindowsReplayRejectsUnauthorizedFileACL(t *testing.T) {
	path := filepath.Join(newReplayTestDir(t), "insecure.json")
	if err := os.WriteFile(path, []byte(`{"version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestFileACL(path, "(A;;FA;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if err := secureReplayFile(path); err == nil {
		t.Fatal("replay file with BUILTIN\\Users access was accepted")
	}
}

func TestWindowsReplayRejectsInsecurePreexistingReplayState(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	first := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), first, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestFileACL(path, "(A;;FA;;;BU)"); err != nil {
		t.Fatal(err)
	}
	second := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), second, time.Now().UTC().Add(time.Minute)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("insecure pre-existing replay state error = %v, want fail-closed ErrReplayUnavailable", err)
	}
}

func TestWindowsReplayRejectsInsecurePreexistingLockFile(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	first := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), first, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestFileACL(path+".lock", "(A;;FA;;;BU)"); err != nil {
		t.Fatal(err)
	}
	second := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), second, time.Now().UTC().Add(time.Minute)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("insecure pre-existing replay lock error = %v, want fail-closed ErrReplayUnavailable", err)
	}
}

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


func setReplayTestFileOwner(path string, sidText string) error {
	sid, err := windows.StringToSid(sidText)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		sid,
		nil,
		nil,
		nil,
	)
}

func TestWindowsReplayCleansOrphanLockStagingAndRepairsOwner(t *testing.T) {
	path := newReplayTestPath(t)
	if err := secureReplayDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), replayStagingPattern(path, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	tempPath := file.Name()
	if _, err := file.Write([]byte("orphaned Windows lock bootstrap")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	// A stale owner is repairable only after the object is proven to be inside
	// the protected store directory; the existing DACL is not rewritten.
	if err := setReplayTestFileOwner(tempPath, "S-1-5-32-544"); err != nil {
		t.Skipf("runner cannot assign the alternate Administrators owner: %v", err)
	}
	if err := secureReplayFile(tempPath); err == nil {
		t.Fatal("staging file with a foreign owner passed ACL verification before owner recovery")
	}

	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("windowsorphan001"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatalf("replay initialization did not recover the orphan lock staging file: %v", err)
	}
	if _, err := os.Lstat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Windows orphan lock staging file remains after owner recovery: %v", err)
	}
}

func TestWindowsReplayCleansLockBootstrapOrphanAfterProcessCrash(t *testing.T) {
	path := newReplayTestPath(t)
	startAndTerminateReplayInitializationProcess(t, path, "lock_staging")
	matches, err := filepath.Glob(replayStagingPattern(path, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("crashed lock bootstrap left %d staging files, want 1", len(matches))
	}
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("windowscrash0001"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatalf("replay store did not recover after lock bootstrap crash: %v", err)
	}
	if _, err := os.Lstat(matches[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crashed Windows lock staging file remains: %v", err)
	}
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

//go:build windows

package portforward

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

func TestWindowsReplayLockBootstrapCrashHelper(t *testing.T) {
	path := os.Getenv("WEDECENT_REPLAY_LOCK_CRASH_PATH")
	if path == "" {
		return
	}
	readyPath := os.Getenv("WEDECENT_REPLAY_LOCK_CRASH_READY")
	stopPath := os.Getenv("WEDECENT_REPLAY_LOCK_CRASH_STOP")
	if readyPath == "" || stopPath == "" {
		t.Fatal("Windows lock crash helper requires readiness and stop paths")
	}
	unlock, err := lockReplayBootstrapFile(path)
	if err != nil {
		t.Fatalf("acquire replay bootstrap lock: %v", err)
	}
	defer unlock()
	file, err := os.CreateTemp(filepath.Dir(path), replayStagingPattern(path, "lock"))
	if err != nil {
		t.Fatalf("create pre-publication lock staging file: %v", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := setReplayFileOwner(file.Name()); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := secureReplayFile(file.Name()); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("crashed before publishing replay lock")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	activePath := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(readyPath, []byte(activePath), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(stopPath); err == nil {
			os.Exit(23)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect Windows lock crash stop marker: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWindowsReplayCleansLockBootstrapOrphanAfterProcessCrash(t *testing.T) {
	path := newReplayTestPath(t)
	readyPath := path + ".lock-crash-ready"
	stopPath := path + ".lock-crash-stop"
	var output bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsReplayLockBootstrapCrashHelper$")
	cmd.Env = append(os.Environ(),
		"WEDECENT_REPLAY_LOCK_CRASH_PATH="+path,
		"WEDECENT_REPLAY_LOCK_CRASH_READY="+readyPath,
		"WEDECENT_REPLAY_LOCK_CRASH_STOP="+stopPath,
	)
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Windows lock bootstrap crash helper: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = os.WriteFile(stopPath, []byte("stop"), 0o600)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = os.Remove(readyPath)
		_ = os.Remove(stopPath)
	})

	deadline := time.Now().Add(10 * time.Second)
	var orphanPath string
	for {
		data, readErr := os.ReadFile(readyPath)
		if readErr == nil {
			if len(data) > 0 {
				orphanPath = string(data)
				break
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			t.Fatalf("read Windows lock crash readiness: %v", readErr)
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			waitErr := cmd.Wait()
			t.Fatalf("Windows lock bootstrap helper did not reach crash barrier: wait=%v output=%s", waitErr, output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Lstat(orphanPath); err != nil {
		t.Fatalf("expected orphan lock staging file before recovery: %v", err)
	}
	if err := os.WriteFile(stopPath, []byte("stop"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("Windows lock bootstrap helper exited normally, expected abrupt process exit")
	}

	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("windowscrash0001"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatalf("replay store did not recover after pre-publication lock crash: %v", err)
	}
	if _, err := os.Lstat(orphanPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crashed Windows lock staging file remains: %v", err)
	}
}

func TestWindowsReplayRejectsUnauthorizedOrphanStagingACL(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	first := base64.RawURLEncoding.EncodeToString([]byte("orphanaclfirst01"))
	second := base64.RawURLEncoding.EncodeToString([]byte("orphanaclsecond1"))
	expiry := time.Now().UTC().Add(time.Minute)
	if err := replay.ConsumePortForwardAuthorization(context.Background(), first, expiry); err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), replayStagingPattern(path, "replay"))
	if err != nil {
		t.Fatal(err)
	}
	orphanPath := file.Name()
	if _, err := file.Write([]byte("orphan with an unauthorized ACL")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestFileACL(orphanPath, "(A;;FA;;;BU)"); err != nil {
		t.Fatal(err)
	}

	err = replay.ConsumePortForwardAuthorization(context.Background(), second, expiry)
	if !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("unauthorized orphan staging ACL error = %v, want fail-closed ErrReplayUnavailable", err)
	}
	if _, err := os.Lstat(orphanPath); err != nil {
		t.Fatalf("cleanup removed or lost staging file with unauthorized ACL: %v", err)
	}
	snapshot, err := readReplaySnapshot(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshot.Entries[first]; !ok {
		t.Fatal("unauthorized staging ACL handling lost existing replay state")
	}
	if _, ok := snapshot.Entries[second]; ok {
		t.Fatal("authorization was consumed despite unauthorized staging ACL")
	}
}

func TestWindowsReplayRejectsInsecurePreexistingBootstrapLock(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	first := base64.RawURLEncoding.EncodeToString([]byte("bootstrapfirst01"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), first, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestFileACL(path+".lock.bootstrap", "(A;;FA;;;BU)"); err != nil {
		t.Fatal(err)
	}
	second := base64.RawURLEncoding.EncodeToString([]byte("bootstrapsecond1"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), second, time.Now().UTC().Add(time.Minute)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("insecure bootstrap lock ACL error = %v, want fail-closed ErrReplayUnavailable", err)
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

func TestWindowsReplayRepairsBootstrapLockOwnerAfterInterruptedCreation(t *testing.T) {
	path := newReplayTestPath(t)
	if err := secureReplayDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	bootstrapPath := path + ".lock.bootstrap"
	file, err := os.OpenFile(bootstrapPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("created before the creator crashed")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestFileOwner(bootstrapPath, "S-1-5-32-544"); err != nil {
		t.Skipf("runner cannot assign the alternate Administrators owner: %v", err)
	}
	if err := verifyReplayDACL(bootstrapPath); err != nil {
		t.Fatalf("restrictive inherited DACL rejected before owner repair: %v", err)
	}
	if err := secureReplayFile(bootstrapPath); err == nil {
		t.Fatal("bootstrap lock with interrupted owner assignment passed before repair")
	}
	unlock, err := lockReplayBootstrapFile(path)
	if err != nil {
		t.Fatalf("bootstrap lock owner recovery failed: %v", err)
	}
	if err := secureReplayFile(bootstrapPath); err != nil {
		t.Fatalf("bootstrap lock owner was not repaired: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("bootstrap lock release failed: %v", err)
	}
}

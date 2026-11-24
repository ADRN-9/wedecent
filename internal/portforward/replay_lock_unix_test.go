//go:build !windows

package portforward

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixReplayLockDeletionAcrossProcessesFailsClosed(t *testing.T) {
	path := filepath.Join(newReplayTestDir(t), "replay.json")
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := "MDEyMzQ1Njc4OWFiY2RlZg"
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	unlock, _, err := lockReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unlock(); err != nil {
			t.Errorf("release parent replay lock: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUnixReplayLockDeletionProcessHelper$")
	cmd.Env = append(os.Environ(), "WEDECENT_REPLAY_LOCK_DELETE_HELPER_PATH="+path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("separate-process lock deletion helper failed: %v\n%s", err, output)
	}
	anchorInfo, err := os.Lstat(path + ".lock.anchor")
	if err != nil {
		t.Fatalf("persistent lock anchor was removed: %v", err)
	}
	aliasInfo, err := os.Lstat(path + ".lock")
	if err != nil {
		t.Fatalf("helper did not replace visible lock alias: %v", err)
	}
	if os.SameFile(anchorInfo, aliasInfo) {
		t.Fatal("helper did not replace the visible lock alias with a distinct inode")
	}
	if err := secureReplayFile(path + ".lock.anchor"); err != nil {
		t.Fatalf("persistent lock anchor was weakened: %v", err)
	}
	if _, _, err := lockReplayFile(path); err == nil {
		t.Fatal("replay lock deletion was not rejected after initialization")
	}
}

func TestUnixReplayLockDeletionProcessHelper(t *testing.T) {
	path := os.Getenv("WEDECENT_REPLAY_LOCK_DELETE_HELPER_PATH")
	if path == "" {
		return
	}
	lockPath := path + ".lock"
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("delete visible lock alias: %v", err)
	}
	replacement, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create replacement lock inode: %v", err)
	}
	if err := replacement.Chmod(0o600); err != nil {
		_ = replacement.Close()
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	unlock, _, err := lockReplayFile(path)
	if err == nil {
		if unlockErr := unlock(); unlockErr != nil {
			t.Fatalf("unlock unexpectedly acquired replacement inode: %v", unlockErr)
		}
		t.Fatal("lock acquisition succeeded after lock alias deletion")
	}
}

func TestUnixReplayOSLockWaitHonorsCancellation(t *testing.T) {
	path := filepath.Join(newReplayTestDir(t), "replay.json")
	unlock, _, err := lockReplayFileOSContext(context.Background(), path, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unlock(); err != nil {
			t.Errorf("release OS replay lock: %v", err)
		}
	}()

	contention := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := lockReplayFileOSContext(ctx, path, path, func() {
			select {
			case contention <- struct{}{}:
			default:
			}
		})
		done <- err
	}()
	select {
	case <-contention:
	case <-time.After(2 * time.Second):
		t.Fatal("OS lock waiter did not report contention")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled OS lock error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OS lock waiter did not honor cancellation")
	}
}

func TestUnixReplayLockAnchorHasPrivateOwnership(t *testing.T) {
	path := filepath.Join(newReplayTestDir(t), "replay.json")
	unlock, _, err := lockReplayFileOSContext(context.Background(), path, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	for _, lockPath := range []string{path + ".lock", path + ".lock.anchor"} {
		if err := secureReplayFile(lockPath); err != nil {
			t.Fatalf("lock metadata %s is not private: %v", filepath.Base(lockPath), err)
		}
	}
}

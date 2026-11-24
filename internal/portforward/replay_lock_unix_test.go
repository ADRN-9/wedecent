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
	path := filepath.Join(newReplayTestDir(t), "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := store.LockTransition(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parentLockHeld := true
	defer func() {
		if parentLockHeld {
			if err := unlock(); err != nil {
				t.Errorf("release parent transition lock: %v", err)
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUnixReplayLockDeletionProcessHelper$")
	cmd.Env = append(os.Environ(), "WEDECENT_REPLAY_LOCK_DELETE_HELPER_PATH="+path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("separate-process transition lock deletion helper failed: %v\n%s", err, output)
	}
	lockPath := path + ".finalize.lock"
	anchorPath := lockPath + ".anchor"
	markerPath := lockPath + ".marker"
	anchorInfo, err := os.Lstat(anchorPath)
	if err != nil {
		t.Fatalf("persistent transition lock anchor was removed: %v", err)
	}
	markerInfo, err := os.Lstat(markerPath)
	if err != nil || !os.SameFile(anchorInfo, markerInfo) {
		t.Fatalf("persistent transition lock marker changed: %v", err)
	}
	aliasInfo, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatalf("helper did not replace visible transition lock alias: %v", err)
	}
	if os.SameFile(anchorInfo, aliasInfo) {
		t.Fatal("helper did not replace the visible transition lock alias with a distinct inode")
	}
	if err := secureReplayFile(anchorPath); err != nil {
		t.Fatalf("persistent transition lock anchor was weakened: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatalf("release parent transition lock: %v", err)
	}
	parentLockHeld = false
	if _, err := store.LockTransition(context.Background()); err == nil {
		t.Fatal("transition lock inode replacement was not rejected after initialization")
	}
}

func TestUnixReplayLockDeletionProcessHelper(t *testing.T) {
	path := os.Getenv("WEDECENT_REPLAY_LOCK_DELETE_HELPER_PATH")
	if path == "" {
		return
	}
	lockPath := path + ".finalize.lock"
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("delete visible transition lock alias: %v", err)
	}
	replacement, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create replacement transition lock inode: %v", err)
	}
	if err := replacement.Chmod(0o600); err != nil {
		_ = replacement.Close()
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileCheckpointPendingStore(path)
	if err == nil {
		unlock, lockErr := store.LockTransition(context.Background())
		if lockErr == nil {
			if unlockErr := unlock(); unlockErr != nil {
				t.Fatalf("unlock unexpectedly acquired replacement inode: %v", unlockErr)
			}
			t.Fatal("transition lock acquisition succeeded after alias replacement")
		}
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
	for _, lockPath := range []string{path + ".lock", path + ".lock.anchor", path + ".lock.marker"} {
		if err := secureReplayFile(lockPath); err != nil {
			t.Fatalf("lock metadata %s is not private: %v", filepath.Base(lockPath), err)
		}
	}
}

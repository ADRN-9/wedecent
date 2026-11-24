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
	if _, err := os.Lstat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("helper did not delete visible lock alias: %v", err)
	}
	if err := secureReplayFile(path + ".lock.anchor"); err != nil {
		t.Fatalf("persistent lock anchor was removed or weakened: %v", err)
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
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatalf("delete visible lock alias: %v", err)
	}
	unlock, _, err := lockReplayFile(path)
	if err == nil {
		if unlockErr := unlock(); unlockErr != nil {
			t.Fatalf("unlock unexpectedly acquired replacement inode: %v", unlockErr)
		}
		t.Fatal("lock acquisition succeeded after lock alias deletion")
	}
}

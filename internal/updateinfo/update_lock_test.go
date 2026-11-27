package updateinfo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplyVerifiedManifestSerializesIndependentStores(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 21
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	statePath := StatePath(privateTempDir(t))
	firstStore := NewStateStore(statePath)
	secondStore := NewStateStore(statePath)
	verified := testVerifiedUpdate(t, firstStore, manifest, archive, 0)

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	executor := InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return nil
	})
	verify := func(context.Context, string) error { return nil }

	first := make(chan error, 1)
	go func() {
		first <- firstStore.applyVerifiedManifest(context.Background(), verified, path, 0, verify, executor)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first updater did not start")
	}

	second := make(chan error, 1)
	go func() {
		second <- secondStore.applyVerifiedManifest(context.Background(), verified, path, 0, verify, executor)
	}()
	select {
	case err := <-second:
		t.Fatalf("second updater returned before first released lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first apply error = %v", err)
	}
	if err := <-second; !errors.Is(err, ErrRollback) {
		t.Fatalf("second apply error = %v, want ErrRollback", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("executor calls = %d, want 1", got)
	}
}

func TestUpdateLockHelperProcess(t *testing.T) {
	if os.Getenv("WEDECENT_UPDATE_LOCK_HELPER") != "1" {
		return
	}
	release, err := acquireUpdateLock(context.Background(), os.Getenv("WEDECENT_UPDATE_LOCK_PATH"))
	if err != nil {
		fmt.Fprintln(os.Stdout, "LOCK_ERROR")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, "LOCKED")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	release()
	os.Exit(0)
}

func TestUpdateLockSerializesSeparateProcesses(t *testing.T) {
	statePath := StatePath(privateTempDir(t))
	command := exec.Command(os.Args[0], "-test.run=^TestUpdateLockHelperProcess$")
	command.Env = append(os.Environ(),
		"WEDECENT_UPDATE_LOCK_HELPER=1",
		"WEDECENT_UPDATE_LOCK_PATH="+statePath,
	)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "LOCKED\n" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("lock helper output = %q, error = %v", line, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if release, err := acquireUpdateLock(ctx, statePath); err == nil {
		release()
		t.Fatal("second process acquired an already-held update lock")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second lock error = %v, want deadline exceeded", err)
	}

	if _, err := fmt.Fprintln(stdin, "release"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	if err := command.Wait(); err != nil {
		t.Fatalf("lock helper failed: %v", err)
	}
	release, err := acquireUpdateLock(context.Background(), statePath)
	if err != nil {
		t.Fatalf("lock was not released by helper process: %v", err)
	}
	release()
}

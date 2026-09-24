package updateinfo

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplyVerifiedInstallerSerializesIndependentStores(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 21
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	statePath := StatePath(privateTempDir(t))
	firstStore := NewStateStore(statePath)
	secondStore := NewStateStore(statePath)

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	executor := InstallerExecutorFunc(func(context.Context, VerifiedInstallerPackage) error {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return nil
	})
	verify := func(context.Context, string) error { return nil }

	first := make(chan error, 1)
	go func() {
		first <- firstStore.ApplyVerifiedInstaller(context.Background(), manifest, path, 0, verify, executor)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first updater did not start")
	}

	second := make(chan error, 1)
	go func() {
		second <- secondStore.ApplyVerifiedInstaller(context.Background(), manifest, path, 0, verify, executor)
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

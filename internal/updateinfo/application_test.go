package updateinfo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplyVerifiedInstallerCommitsSequenceAfterSuccess(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 7
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	stateDir := privateTempDir(t)
	store := NewStateStore(StatePath(stateDir))
	verified, _, _, _ := testVerifiedManifest(t, manifest, store)

	called := false
	err := store.ApplyVerifiedManifest(
		context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(_ context.Context, pkg VerifiedInstallerPackage) error {
			called = true
			if pkg.Version != manifest.Version {
				t.Fatalf("executor version = %q, want %q", pkg.Version, manifest.Version)
			}
			if _, err := os.Stat(filepath.Join(pkg.Dir, "Install-WeDecent.ps1")); err != nil {
				t.Fatalf("verified installer missing inside callback: %v", err)
			}
			state, err := storeStateWithoutLock(store.Path)
			if err != nil {
				t.Fatalf("load state during executor: %v", err)
			}
			if state.StableSequence != 0 {
				t.Fatalf("sequence advanced before installer success: %d", state.StableSequence)
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("ApplyVerifiedInstaller() error = %v", err)
	}
	if !called {
		t.Fatal("installer executor was not called")
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != manifest.Sequence {
		t.Fatalf("stable sequence = %d, want %d", state.StableSequence, manifest.Sequence)
	}
}

func TestApplyVerifiedInstallerFailureDoesNotCommitSequence(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 8
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified, _, _, _ := testVerifiedManifest(t, manifest, store)

	err := store.ApplyVerifiedManifest(
		context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, VerifiedInstallerPackage) error {
			return errors.New("secret privileged stderr")
		}),
	)
	if !errors.Is(err, ErrInstallerApply) {
		t.Fatalf("error = %v, want ErrInstallerApply", err)
	}
	if strings.Contains(err.Error(), "secret privileged stderr") {
		t.Fatalf("raw executor error leaked: %v", err)
	}
	state, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.StableSequence != 0 {
		t.Fatalf("failed installer advanced sequence to %d", state.StableSequence)
	}
}

func TestApplyVerifiedInstallerRejectsRollbackBeforeExecution(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 10
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	if err := store.Advance(10); err != nil {
		t.Fatal(err)
	}
	verified, _, _, _ := testVerifiedManifest(t, manifest, store)

	called := false
	err := store.ApplyVerifiedManifest(
		context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, VerifiedInstallerPackage) error {
			called = true
			return nil
		}),
	)
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("error = %v, want ErrRollback", err)
	}
	if called {
		t.Fatal("rollback candidate reached installer executor")
	}
}

func TestApplyVerifiedInstallerIgnoresCancellationAfterMutationStarts(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 11
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified, _, _, _ := testVerifiedManifest(t, manifest, store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := store.ApplyVerifiedManifest(
		ctx, verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(execCtx context.Context, _ VerifiedInstallerPackage) error {
			cancel()
			if execCtx.Err() != nil {
				t.Fatalf("executor context inherited caller cancellation: %v", execCtx.Err())
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("ApplyVerifiedInstaller() error = %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != manifest.Sequence {
		t.Fatalf("stable sequence = %d, want %d", state.StableSequence, manifest.Sequence)
	}
}

func TestApplyVerifiedInstallerReportsSequenceCommitFailureAfterInstall(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 12
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	stateDir := privateTempDir(t)
	statePath := StatePath(stateDir)
	store := NewStateStore(statePath)
	verified, _, _, _ := testVerifiedManifest(t, manifest, store)
	called := false

	err := store.ApplyVerifiedManifest(
		context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, VerifiedInstallerPackage) error {
			called = true
			if err := os.Remove(statePath); err != nil {
				t.Fatalf("remove update state before blocker: %v", err)
			}
			if err := os.Mkdir(statePath, 0o700); err != nil {
				t.Fatalf("create state-path blocker: %v", err)
			}
			return nil
		}),
	)
	if !called {
		t.Fatal("installer executor was not called")
	}
	if !errors.Is(err, ErrSequenceCommit) {
		t.Fatalf("error = %v, want ErrSequenceCommit", err)
	}
}

func TestApplyVerifiedInstallerSerializesSameSequence(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 13
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified, _, _, _ := testVerifiedManifest(t, manifest, store)
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

	firstCtx, cancelFirst := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelFirst()
	first := make(chan error, 1)
	go func() {
		first <- store.ApplyVerifiedManifest(firstCtx, verified, path, 0, func(context.Context, string) error { return nil }, executor)
	}()
	select {
	case <-started:
	case err := <-first:
		t.Fatalf("first apply ended before installer start: %v", err)
	case <-firstCtx.Done():
		err := <-first
		t.Fatalf("first installer did not start before context deadline: %v", err)
	}

	second := make(chan error, 1)
	go func() {
		second <- store.ApplyVerifiedManifest(context.Background(), verified, path, 0, func(context.Context, string) error { return nil }, executor)
	}()
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

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func storeStateWithoutLock(path string) (State, error) {
	return loadState(path)
}

func TestApplyVerifiedManifestRejectsConcurrentKeysetRotation(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 17
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified, rootPublic, rootPrivate, keyset := testVerifiedManifest(t, manifest, store)

	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	keyset.Epoch++
	keysetBody, keysetSignature := signKeyset(t, keyset, rootPrivate, now)
	if _, err := store.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, keysetBody, keysetSignature, now); err != nil {
		t.Fatal(err)
	}
	called := false
	err := store.ApplyVerifiedManifest(
		context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, VerifiedInstallerPackage) error {
			called = true
			return nil
		}),
	)
	if !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("changed keyset epoch error = %v, want ErrKeysetRollback", err)
	}
	if called {
		t.Fatal("installer executor ran after concurrent keyset rotation")
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != 0 || state.KeysetEpoch != keyset.Epoch {
		t.Fatalf("state after rejected stale signer = %#v", state)
	}
}

func testVerifiedManifest(t *testing.T, manifest Manifest, store *StateStore) (VerifiedManifest, ed25519.PublicKey, ed25519.PrivateKey, Keyset) {
	t.Helper()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, keyset := keysetFixture(t, now)
	manifestPublic, manifestPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := EncodePublicKey(manifestPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyset.Keys[0].PublicKey = strings.TrimSuffix(string(encodedPublic), "\n")
	keysetBody, keysetSignature := signKeyset(t, keyset, rootPrivate, now)
	verifiedKeyset, err := store.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, keysetBody, keysetSignature, now)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Schema = ManifestSchemaV2
	manifest.SigningKeyID = keyset.Keys[0].ID
	manifest.KeysetEpoch = keyset.Epoch
	manifest.PublishedAt = now.Format(time.RFC3339)
	manifestBytes, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeSignature(ed25519.Sign(manifestPrivate, manifestBytes))
	if err != nil {
		t.Fatal(err)
	}
	verifiedManifest, err := VerifyManifestV2(verifiedKeyset, manifestBytes, signature, now, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := verifiedManifestFrom(verifiedKeyset, verifiedManifest, manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	return capability, rootPublic, rootPrivate, keyset
}

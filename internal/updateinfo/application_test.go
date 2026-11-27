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
		InstallerExecutorFunc(func(_ context.Context, transaction InstallTransaction, pkg VerifiedInstallerPackage) error {
			called = true
			if transaction.ID == "" || transaction.Sequence != manifest.Sequence ||
				transaction.ManifestDigest == "" || transaction.PackageDigest != manifest.InstallerSHA256 {
				t.Fatalf("executor transaction does not bind verified update: %#v", transaction)
			}
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
	if state.PendingInstall != nil {
		t.Fatalf("successful install left pending transaction: %#v", state.PendingInstall)
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
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
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
	if state.PendingInstall == nil {
		t.Fatal("failed installer did not leave a durable recovery journal")
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
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
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
		InstallerExecutorFunc(func(execCtx context.Context, _ InstallTransaction, _ VerifiedInstallerPackage) error {
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
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
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
	executor := InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
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
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
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
	capability, err := VerifyManifestV2Capability(verifiedKeyset, manifestBytes, signature, now, "v0.0.0", 0)
	if err != nil {
		t.Fatal(err)
	}
	return capability, rootPublic, rootPrivate, keyset
}

func TestUnverifiedManifestCannotInvokeInstallerOrAdvanceSequence(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 99
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	var calls atomic.Int32
	executor := InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
		calls.Add(1)
		return nil
	})
	err := store.ApplyVerifiedInstaller(context.Background(), manifest, path, 0,
		func(context.Context, string) error { return nil }, executor)
	if !errors.Is(err, ErrUnverifiedManifest) {
		t.Fatalf("unverified admission error = %v, want ErrUnverifiedManifest", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("executor calls = %d, want 0", calls.Load())
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != 0 {
		t.Fatalf("unverified manifest advanced sequence to %d", state.StableSequence)
	}
}

func TestVerifiedManifestCapabilityRejectsMutation(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 100
	manifest.InstallerSHA256 = sha256Hex(archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified, _, _, _ := testVerifiedManifest(t, manifest, store)
	verified.manifest.Sequence++
	if err := verified.validate(); !errors.Is(err, ErrUnverifiedManifest) {
		t.Fatalf("mutated capability validation error = %v, want ErrUnverifiedManifest", err)
	}
}

type testInstallerRecovery func(context.Context, InstallTransaction) (InstallRecoveryResult, error)

func (f testInstallerRecovery) Recover(ctx context.Context, transaction InstallTransaction) (InstallRecoveryResult, error) {
	return f(ctx, transaction)
}

func TestInterruptedInstallerIsJournaledAndRecoveredAfterRestart(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 101
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	statePath := StatePath(privateTempDir(t))
	store := NewStateStore(statePath)
	verified, _, _, _ := testVerifiedManifest(t, manifest, store)

	err := store.ApplyVerifiedManifest(context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
			return errors.New("simulated interrupted installer")
		}))
	if !errors.Is(err, ErrInstallerApply) {
		t.Fatalf("apply error = %v, want ErrInstallerApply", err)
	}
	restarted := NewStateStore(statePath)
	state, err := restarted.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != 0 || state.PendingInstall == nil {
		t.Fatalf("interrupted state = %#v; want pending transaction and unchanged sequence", state)
	}
	pending := *state.PendingInstall
	if pending.Sequence != manifest.Sequence || pending.TargetVersion != manifest.Version ||
		pending.PackageDigest != manifest.InstallerSHA256 || pending.ManifestDigest == "" {
		t.Fatalf("pending transaction does not bind update: %#v", pending)
	}

	err = restarted.ApplyVerifiedManifest(context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error { return nil }))
	if !errors.Is(err, ErrInstallRecoveryRequired) {
		t.Fatalf("second apply error = %v, want ErrInstallRecoveryRequired", err)
	}

	err = restarted.RecoverPendingInstall(context.Background(), testInstallerRecovery(
		func(_ context.Context, got InstallTransaction) (InstallRecoveryResult, error) {
			if got.ID != pending.ID {
				t.Fatalf("recovery transaction ID = %q, want %q", got.ID, pending.ID)
			}
			return InstallRecoveryApplied, nil
		}))
	if err != nil {
		t.Fatalf("RecoverPendingInstall() error = %v", err)
	}
	state, err = restarted.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingInstall != nil || state.StableSequence != manifest.Sequence {
		t.Fatalf("recovered state = %#v", state)
	}
}

func TestUnknownInstallerRecoveryRemainsFailClosed(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 102
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified, rootPublic, rootPrivate, keyset := testVerifiedManifest(t, manifest, store)
	if err := store.ApplyVerifiedManifest(context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
			return errors.New("interrupted")
		})); !errors.Is(err, ErrInstallerApply) {
		t.Fatalf("apply error = %v, want ErrInstallerApply", err)
	}
	if err := store.RecoverPendingInstall(context.Background(), testInstallerRecovery(
		func(context.Context, InstallTransaction) (InstallRecoveryResult, error) {
			return InstallRecoveryUnknown, nil
		})); !errors.Is(err, ErrInstallRecoveryRequired) {
		t.Fatalf("unknown recovery error = %v, want ErrInstallRecoveryRequired", err)
	}
	if err := store.Advance(200); !errors.Is(err, ErrInstallRecoveryRequired) {
		t.Fatalf("sequence advance during pending install = %v, want ErrInstallRecoveryRequired", err)
	}
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	keyset.Epoch++
	keysetBody, keysetSignature := signKeyset(t, keyset, rootPrivate, now)
	if _, err := store.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, keysetBody, keysetSignature, now); !errors.Is(err, ErrInstallRecoveryRequired) {
		t.Fatalf("keyset rotation during pending install = %v, want ErrInstallRecoveryRequired", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingInstall == nil || state.StableSequence != 0 {
		t.Fatalf("unknown recovery changed durable state: %#v", state)
	}
}

func TestInstallerRecoveryNotAppliedClearsJournalOnlyAfterRepair(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 103
	manifest.InstallerSHA256 = sha256Hex(archive)
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified, _, _, _ := testVerifiedManifest(t, manifest, store)
	if err := store.ApplyVerifiedManifest(context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
			return errors.New("interrupted")
		})); !errors.Is(err, ErrInstallerApply) {
		t.Fatalf("apply error = %v, want ErrInstallerApply", err)
	}
	if err := store.RecoverPendingInstall(context.Background(), testInstallerRecovery(
		func(_ context.Context, transaction InstallTransaction) (InstallRecoveryResult, error) {
			if transaction.RecoveryState != "recovery-required" {
				t.Fatalf("recovery state = %q, want recovery-required", transaction.RecoveryState)
			}
			return InstallRecoveryNotApplied, nil
		})); err != nil {
		t.Fatalf("RecoverPendingInstall() error = %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingInstall != nil || state.StableSequence != 0 {
		t.Fatalf("not-applied recovery state = %#v", state)
	}
}

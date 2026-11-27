package updateinfo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testVerifiedUpdate(t *testing.T, store *StateStore, manifest Manifest, archive []byte, highest uint64) VerifiedManifest {
	t.Helper()
	fixture := newDiscoveryFixture(t)
	keyset, err := store.VerifyAndAdvanceKeyset(context.Background(), fixture.keyset.RootKeyID, fixture.rootPublic, fixture.keysetBody, fixture.keysetSignature, fixture.now)
	if err != nil {
		t.Fatalf("persist trusted keyset: %v", err)
	}
	manifest.Schema = ManifestSchemaV2
	manifest.SigningKeyID = fixture.keyset.Keys[0].ID
	manifest.KeysetEpoch = fixture.keyset.Epoch
	manifest.PublishedAt = fixture.now.Format(time.RFC3339)
	manifest.InstallerSHA256 = sha256Hex(archive)
	body, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatalf("encode signed manifest: %v", err)
	}
	signature, err := EncodeSignature(ed25519.Sign(fixture.manifestPrivate, body))
	if err != nil {
		t.Fatalf("encode manifest signature: %v", err)
	}
	verified, err := VerifyManifestV2Capability(keyset, body, signature, fixture.now, "v0.0.0", highest)
	if err != nil {
		t.Fatalf("verify manifest capability: %v", err)
	}
	return verified
}

func TestApplyVerifiedManifestCommitsSequenceAfterSuccess(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 7
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified := testVerifiedUpdate(t, store, manifest, archive, 0)

	called := false
	err := store.applyVerifiedManifest(context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(_ context.Context, transaction InstallTransaction, pkg VerifiedInstallerPackage) error {
			called = true
			if transaction.Phase != InstallPhaseExecuting || transaction.Sequence != manifest.Sequence ||
				transaction.ManifestDigest != verified.ManifestDigest() || transaction.PackageDigest != verified.Manifest().InstallerSHA256 {
				t.Fatalf("executor transaction does not bind verified update: %#v", transaction)
			}
			if pkg.Version() != manifest.Version {
				t.Fatalf("executor version = %q, want %q", pkg.Version(), manifest.Version)
			}
			if _, err := os.Stat(filepath.Join(pkg.Directory(), "Install-WeDecent.ps1")); err != nil {
				t.Fatalf("verified installer missing inside callback: %v", err)
			}
			state, err := storeStateWithoutLock(store.Path)
			if err != nil {
				t.Fatalf("load state during executor: %v", err)
			}
			if state.StableSequence != 0 || state.PendingInstall == nil || state.PendingInstall.ID != transaction.ID {
				t.Fatalf("journal/sequence not durable before execution: %#v", state)
			}
			return nil
		}))
	if err != nil {
		t.Fatalf("apply verified manifest: %v", err)
	}
	if !called {
		t.Fatal("installer executor was not called")
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != manifest.Sequence || state.PendingInstall != nil {
		t.Fatalf("committed state = %#v", state)
	}
}

func TestForgedVerifiedManifestCannotInvokeExecutorOrAdvanceSequence(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 8
	manifest.Schema = ManifestSchemaV2
	manifest.SigningKeyID = "forged-signer"
	manifest.KeysetEpoch = 1
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	// Package-internal adversary constructs a structurally plausible capability
	// without calling the signature-verification constructor.
	forged := VerifiedManifest{manifest: manifest, signerID: manifest.SigningKeyID,
		keysetEpoch: manifest.KeysetEpoch, keysetDigest: strings.Repeat("a", 64),
		manifestDigest: strings.Repeat("b", 64), previousVersion: "v0.0.0"}
	called := false
	err := store.applyVerifiedManifest(context.Background(), forged, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
			called = true
			return nil
		}))
	if err == nil || called {
		t.Fatalf("forged capability accepted: err=%v called=%v", err, called)
	}
	state, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if state.StableSequence != 0 || state.PendingInstall != nil {
		t.Fatalf("forged capability changed state: %#v", state)
	}
}

func TestApplyVerifiedManifestWrongSignerRejectedBeforeExecutor(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 9
	fixture := newDiscoveryFixture(t)
	store := NewStateStore(StatePath(privateTempDir(t)))
	keyset, err := store.VerifyAndAdvanceKeyset(context.Background(), fixture.keyset.RootKeyID, fixture.rootPublic, fixture.keysetBody, fixture.keysetSignature, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Schema = ManifestSchemaV2
	manifest.SigningKeyID = fixture.keyset.Keys[0].ID
	manifest.KeysetEpoch = fixture.keyset.Epoch
	manifest.PublishedAt = fixture.now.Format(time.RFC3339)
	manifest.InstallerSHA256 = sha256Hex(archive)
	body, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeSignature(ed25519.Sign(wrongPrivate, body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifestV2Capability(keyset, body, signature, fixture.now, "v0.0.0", 0); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong signer error = %v, want ErrInvalidSignature", err)
	}
}

func TestApplyVerifiedManifestFailureLeavesRecoveryJournalAndNoSequenceAdvance(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 10
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified := testVerifiedUpdate(t, store, manifest, archive, 0)
	err := store.applyVerifiedManifest(context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
			return errors.New("secret privileged stderr")
		}))
	if !errors.Is(err, ErrInstallerApply) || strings.Contains(err.Error(), "secret privileged stderr") {
		t.Fatalf("installer failure = %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != 0 || state.PendingInstall == nil || state.PendingInstall.Phase != InstallPhaseRecoveryRequired {
		t.Fatalf("failed installer state = %#v", state)
	}
	if err := store.Advance(11); !errors.Is(err, ErrInstallRecoveryRequired) {
		t.Fatalf("manual sequence advance with pending install = %v", err)
	}
}

type testInstallerRecovery func(context.Context, InstallTransaction) (InstallRecoveryResult, error)

func (f testInstallerRecovery) Recover(ctx context.Context, transaction InstallTransaction) (InstallRecoveryResult, error) {
	return f(ctx, transaction)
}

func (f testInstallerRecovery) Commit(context.Context, InstallTransaction) error { return nil }

func TestInterruptedInstallRestartRecoveryApplied(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 11
	path := writeStagedArchive(t, archive)
	statePath := StatePath(privateTempDir(t))
	store := NewStateStore(statePath)
	verified := testVerifiedUpdate(t, store, manifest, archive, 0)
	if err := store.applyVerifiedManifest(context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
			return errors.New("simulated process interruption")
		})); !errors.Is(err, ErrInstallerApply) {
		t.Fatalf("apply error = %v", err)
	}

	restarted := NewStateStore(statePath)
	state, err := restarted.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingInstall == nil || state.StableSequence != 0 {
		t.Fatalf("restart state = %#v", state)
	}
	pending := *state.PendingInstall
	if err := restarted.applyVerifiedManifest(context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error { return nil })); !errors.Is(err, ErrInstallRecoveryRequired) {
		t.Fatalf("new install during recovery = %v", err)
	}
	if err := restarted.RecoverPendingInstall(context.Background(), testInstallerRecovery(func(_ context.Context, got InstallTransaction) (InstallRecoveryResult, error) {
		if got.ID != pending.ID || got.Phase != InstallPhaseRecoveryRequired {
			t.Fatalf("recovery transaction = %#v", got)
		}
		return InstallRecoveryApplied, nil
	})); err != nil {
		t.Fatalf("recover applied install: %v", err)
	}
	state, err = restarted.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingInstall != nil || state.StableSequence != manifest.Sequence {
		t.Fatalf("recovered state = %#v", state)
	}
}

func TestUnknownRecoveryRemainsFailClosedAndNotAppliedKeepsSequence(t *testing.T) {
	for _, result := range []InstallRecoveryResult{InstallRecoveryUnknown, InstallRecoveryNotApplied} {
		manifest, archive := buildInstallerPackageFixture(t, nil)
		manifest.Sequence = 12
		path := writeStagedArchive(t, archive)
		store := NewStateStore(StatePath(privateTempDir(t)))
		verified := testVerifiedUpdate(t, store, manifest, archive, 0)
		if err := store.applyVerifiedManifest(context.Background(), verified, path, 0,
			func(context.Context, string) error { return nil },
			InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
				return errors.New("interrupted")
			})); !errors.Is(err, ErrInstallerApply) {
			t.Fatalf("apply error = %v", err)
		}
		err := store.RecoverPendingInstall(context.Background(), testInstallerRecovery(func(context.Context, InstallTransaction) (InstallRecoveryResult, error) { return result, nil }))
		state, loadErr := store.Load()
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if result == InstallRecoveryUnknown {
			if !errors.Is(err, ErrInstallRecoveryRequired) || state.PendingInstall == nil || state.StableSequence != 0 {
				t.Fatalf("unknown recovery err=%v state=%#v", err, state)
			}
		} else if err != nil || state.PendingInstall != nil || state.StableSequence != 0 {
			t.Fatalf("not-applied recovery err=%v state=%#v", err, state)
		}
	}
}

func TestApplyVerifiedManifestRejectsStaleKeysetAfterRotation(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 13
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified := testVerifiedUpdate(t, store, manifest, archive, 0)
	fixture := newDiscoveryFixture(t)
	rotated := fixture.keyset
	rotated.Epoch++
	body, signature := signKeyset(t, rotated, fixture.rootPrivate, fixture.now)
	if _, err := store.VerifyAndAdvanceKeyset(context.Background(), rotated.RootKeyID, fixture.rootPublic, body, signature, fixture.now); err != nil {
		t.Fatal(err)
	}
	called := false
	err := store.applyVerifiedManifest(context.Background(), verified, path, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error { called = true; return nil }))
	if !errors.Is(err, ErrKeysetRollback) || called {
		t.Fatalf("stale keyset err=%v called=%v", err, called)
	}
}

func TestApplyVerifiedManifestSerializesSameSequence(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 14
	path := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified := testVerifiedUpdate(t, store, manifest, archive, 0)
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
	firstCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	first := make(chan error, 1)
	go func() {
		first <- store.applyVerifiedManifest(firstCtx, verified, path, 0, func(context.Context, string) error { return nil }, executor)
	}()
	select {
	case <-started:
	case err := <-first:
		t.Fatalf("first apply ended before execution: %v", err)
	case <-firstCtx.Done():
		t.Fatalf("first installer did not start: %v", <-first)
	}
	second := make(chan error, 1)
	go func() {
		second <- store.applyVerifiedManifest(context.Background(), verified, path, 0, func(context.Context, string) error { return nil }, executor)
	}()
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := <-second; !errors.Is(err, ErrRollback) {
		t.Fatalf("second apply = %v, want ErrRollback", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("executor calls = %d, want 1", calls.Load())
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

func storeStateWithoutLock(path string) (State, error) { return loadState(path) }

func TestInstallCrashHelper(t *testing.T) {
	phase := os.Getenv("WEDECENT_TEST_INSTALL_CRASH_PHASE")
	if phase == "" {
		return
	}
	stateDir := os.Getenv("WEDECENT_TEST_INSTALL_STATE_DIR")
	store := NewStateStore(StatePath(stateDir))
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 90
	verified := testVerifiedUpdate(t, store, manifest, archive, 0)
	staged := writeStagedArchive(t, archive)
	store.persistState = func(state State) error {
		if err := saveState(store.Path, state); err != nil {
			return err
		}
		if state.PendingInstall != nil && state.PendingInstall.Phase == phase {
			os.Exit(77)
		}
		if phase == "final" && state.PendingInstall == nil && state.StableSequence == manifest.Sequence {
			os.Exit(77)
		}
		return nil
	}
	executor := InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
		if phase == "executor" {
			os.Exit(78)
		}
		return nil
	})
	_ = store.applyVerifiedManifest(context.Background(), verified, staged, 0,
		func(context.Context, string) error { return nil }, executor)
	t.Fatalf("crash helper unexpectedly returned for phase %q", phase)
}

func TestInstallProcessTerminationAtDurableBoundaries(t *testing.T) {
	for _, phase := range []string{"pending", "executing", "executor", "committed", "final"} {
		t.Run(phase, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			cmd := exec.Command(os.Args[0], "-test.run=^TestInstallCrashHelper$")
			cmd.Env = append(os.Environ(),
				"WEDECENT_TEST_INSTALL_CRASH_PHASE="+phase,
				"WEDECENT_TEST_INSTALL_STATE_DIR="+stateDir,
			)
			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("child error = %v, want process termination", err)
			}
			wantExit := 77
			if phase == "executor" {
				wantExit = 78
			}
			if exitErr.ExitCode() != wantExit {
				t.Fatalf("child exit = %d, want %d", exitErr.ExitCode(), wantExit)
			}

			store := NewStateStore(StatePath(stateDir))
			state, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if phase == "final" {
				if state.PendingInstall != nil || state.StableSequence != 90 {
					t.Fatalf("final commit recovery state = %#v", state)
				}
				return
			}
			if state.PendingInstall == nil || state.StableSequence != 0 {
				t.Fatalf("crash did not preserve pending journal without advancing sequence: %#v", state)
			}
			want := InstallRecoveryNotApplied
			if phase == "executing" || phase == "committed" {
				want = InstallRecoveryApplied
			}
			if err := store.RecoverPendingInstall(context.Background(), testInstallerRecovery(
				func(_ context.Context, transaction InstallTransaction) (InstallRecoveryResult, error) {
					if transaction.PreviousVersion != "v0.0.0" || transaction.TargetVersion == "" {
						t.Fatalf("recovery transaction lacks version/backup binding: %#v", transaction)
					}
					return want, nil
				})); err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if err := store.RecoverPendingInstall(context.Background(), testInstallerRecovery(
				func(context.Context, InstallTransaction) (InstallRecoveryResult, error) {
					t.Fatal("completed recovery must be idempotent and must not call adapter again")
					return InstallRecoveryUnknown, nil
				})); err != nil {
				t.Fatalf("second recovery: %v", err)
			}
			state, err = store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if state.PendingInstall != nil {
				t.Fatalf("recovery left pending journal: %#v", state)
			}
			if want == InstallRecoveryApplied && state.StableSequence != 90 {
				t.Fatalf("applied recovery sequence = %d, want 90", state.StableSequence)
			}
			if want == InstallRecoveryNotApplied && state.StableSequence != 0 {
				t.Fatalf("rollback recovery advanced sequence to %d", state.StableSequence)
			}
		})
	}
}

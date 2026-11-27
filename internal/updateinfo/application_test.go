package updateinfo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"encoding/json"
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
	store.readInstalledVersion = func() (string, error) { return "v0.0.0", nil }
	if _, _, err := store.installedSnapshot(context.Background()); err != nil {
		t.Fatalf("load protected installed version: %v", err)
	}
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

type filesystemInstallJournal struct {
	TransactionID string            `json:"transaction_id"`
	PreviousVersion string          `json:"previous_version"`
	TargetVersion string            `json:"target_version"`
	OriginalHashes map[string]string `json:"original_hashes"`
	TargetHashes map[string]string   `json:"target_hashes"`
}

type filesystemInstallerExecutor struct {
	root string
	backupRoot string
	statePath string
	crashAfterFirstReplacement bool
}

func (e filesystemInstallerExecutor) Execute(_ context.Context, transaction InstallTransaction, pkg VerifiedInstallerPackage) error {
	if _, err := os.Stat(e.backupRoot); err == nil { return errors.New("transaction backup already exists") }
	if err := os.MkdirAll(e.backupRoot, 0o700); err != nil { return err }
	journal := filesystemInstallJournal{
		TransactionID: transaction.ID,
		PreviousVersion: transaction.PreviousVersion,
		TargetVersion: transaction.TargetVersion,
		OriginalHashes: map[string]string{},
		TargetHashes: map[string]string{},
	}
	if err := copyTestFile(filepath.Join(e.root, "version.txt"), filepath.Join(e.backupRoot, "version.txt")); err != nil { return err }
	for _, name := range installerBinaries {
		source := filepath.Join(e.root, name)
		backup := filepath.Join(e.backupRoot, name)
		if err := copyTestFile(source, backup); err != nil { return err }
		journal.OriginalHashes[name] = sha256Hex(mustReadTestFile(source))
		journal.TargetHashes[name] = sha256Hex(mustReadTestFile(filepath.Join(pkg.Directory(), name)))
	}
	data, err := json.Marshal(journal)
	if err != nil { return err }
	if err := os.WriteFile(filepath.Join(e.backupRoot, "transaction.json"), append(data, '\n'), 0o600); err != nil { return err }

	for i, name := range installerBinaries {
		if err := replaceTestFile(filepath.Join(pkg.Directory(), name), filepath.Join(e.root, name)); err != nil { return err }
		if e.crashAfterFirstReplacement && i == 0 { os.Exit(78) }
	}
	return os.WriteFile(filepath.Join(e.root, "version.txt"), []byte(transaction.TargetVersion+"\n"), 0o600)
}

func (e filesystemInstallerExecutor) Commit(_ context.Context, transaction InstallTransaction) error {
	state, err := loadState(e.statePath)
	if err != nil { return err }
	if state.PendingInstall == nil || state.PendingInstall.ID != transaction.ID { return ErrInstallRecoveryRequired }
	switch state.PendingInstall.Phase {
	case InstallPhaseCommitted:
		if state.StableSequence != transaction.Sequence || state.InstalledVersion != transaction.TargetVersion || !e.verifyTarget(transaction) {
			return ErrInstallRecoveryRequired
		}
	case InstallPhaseRecoveryRequired:
		if state.StableSequence >= transaction.Sequence || state.InstalledVersion != transaction.PreviousVersion || !e.verifyPrevious(transaction) {
			return ErrInstallRecoveryRequired
		}
	default:
		return ErrInstallRecoveryRequired
	}
	return os.RemoveAll(e.backupRoot)
}

func (e filesystemInstallerExecutor) Recover(_ context.Context, transaction InstallTransaction) (InstallRecoveryResult, error) {
	if _, err := os.Stat(e.backupRoot); errors.Is(err, os.ErrNotExist) {
		if e.verifyPrevious(transaction) { return InstallRecoveryNotApplied, nil }
		return InstallRecoveryUnknown, ErrInstallRecoveryRequired
	} else if err != nil { return InstallRecoveryUnknown, err }

	var journal filesystemInstallJournal
	data, err := os.ReadFile(filepath.Join(e.backupRoot, "transaction.json"))
	if err != nil || json.Unmarshal(data, &journal) != nil ||
		journal.TransactionID != transaction.ID ||
		journal.PreviousVersion != transaction.PreviousVersion ||
		journal.TargetVersion != transaction.TargetVersion {
		return InstallRecoveryUnknown, ErrInstallRecoveryRequired
	}
	if e.verifyTargetWithJournal(journal) { return InstallRecoveryApplied, nil }
	for _, name := range installerBinaries {
		source := filepath.Join(e.backupRoot, name)
		if sha256Hex(mustReadTestFile(source)) != journal.OriginalHashes[name] {
			return InstallRecoveryUnknown, ErrInstallRecoveryRequired
		}
		if err := replaceTestFile(source, filepath.Join(e.root, name)); err != nil { return InstallRecoveryUnknown, err }
	}
	if err := replaceTestFile(filepath.Join(e.backupRoot, "version.txt"), filepath.Join(e.root, "version.txt")); err != nil {
		return InstallRecoveryUnknown, err
	}
	if !e.verifyPreviousWithJournal(journal) { return InstallRecoveryUnknown, ErrInstallRecoveryRequired }
	return InstallRecoveryNotApplied, nil
}

func (e filesystemInstallerExecutor) verifyTarget(transaction InstallTransaction) bool {
	data, err := os.ReadFile(filepath.Join(e.backupRoot, "transaction.json"))
	if err != nil { return false }
	var journal filesystemInstallJournal
	if json.Unmarshal(data, &journal) != nil || journal.TransactionID != transaction.ID { return false }
	return e.verifyTargetWithJournal(journal)
}

func (e filesystemInstallerExecutor) verifyTargetWithJournal(journal filesystemInstallJournal) bool {
	version, err := os.ReadFile(filepath.Join(e.root, "version.txt"))
	if err != nil || strings.TrimSpace(string(version)) != journal.TargetVersion { return false }
	for _, name := range installerBinaries {
		data, err := os.ReadFile(filepath.Join(e.root, name))
		if err != nil || sha256Hex(data) != journal.TargetHashes[name] { return false }
	}
	return true
}

func (e filesystemInstallerExecutor) verifyPrevious(transaction InstallTransaction) bool {
	version, err := os.ReadFile(filepath.Join(e.root, "version.txt"))
	if err != nil || strings.TrimSpace(string(version)) != transaction.PreviousVersion { return false }
	for _, name := range installerBinaries {
		data, err := os.ReadFile(filepath.Join(e.root, name))
		if err != nil || string(data) != "previous:"+name { return false }
	}
	return true
}

func (e filesystemInstallerExecutor) verifyPreviousWithJournal(journal filesystemInstallJournal) bool {
	version, err := os.ReadFile(filepath.Join(e.root, "version.txt"))
	if err != nil || strings.TrimSpace(string(version)) != journal.PreviousVersion { return false }
	for _, name := range installerBinaries {
		data, err := os.ReadFile(filepath.Join(e.root, name))
		if err != nil || sha256Hex(data) != journal.OriginalHashes[name] { return false }
	}
	return true
}

func copyTestFile(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil { return err }
	return os.WriteFile(destination, data, 0o600)
}

func replaceTestFile(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil { return err }
	temp := destination + ".replace"
	if err := os.WriteFile(temp, data, 0o600); err != nil { return err }
	return os.Rename(temp, destination)
}

func mustReadTestFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil { panic(err) }
	return data
}

func preparePreviousInstallation(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil { t.Fatal(err) }
	for _, name := range installerBinaries {
		if err := os.WriteFile(filepath.Join(root, name), []byte("previous:"+name), 0o600); err != nil { t.Fatal(err) }
	}
	if err := os.WriteFile(filepath.Join(root, "version.txt"), []byte("v0.0.0\n"), 0o600); err != nil { t.Fatal(err) }
}

func TestInstallCrashHelper(t *testing.T) {
	phase := os.Getenv("WEDECENT_TEST_INSTALL_CRASH_PHASE")
	if phase == "" { return }
	stateDir := os.Getenv("WEDECENT_TEST_INSTALL_STATE_DIR")
	installDir := filepath.Join(stateDir, "install")
	preparePreviousInstallation(t, installDir)
	store := NewStateStore(StatePath(stateDir))
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 90
	verified := testVerifiedUpdate(t, store, manifest, archive, 0)
	staged := writeStagedArchive(t, archive)
	executor := filesystemInstallerExecutor{
		root: installDir,
		backupRoot: filepath.Join(stateDir, "install-transactions", verified.Manifest().Version),
		statePath: store.Path,
		crashAfterFirstReplacement: phase == "executor",
	}
	store.persistState = func(state State) error {
		if err := saveState(store.Path, state); err != nil { return err }
		if state.PendingInstall != nil && state.PendingInstall.Phase == phase { os.Exit(77) }
		if phase == "final" && state.PendingInstall == nil && state.StableSequence == manifest.Sequence { os.Exit(77) }
		return nil
	}
	_ = store.applyVerifiedManifest(context.Background(), verified, staged, 0,
		func(context.Context, string) error { return nil }, executor)
	t.Fatalf("crash helper unexpectedly returned for phase %q", phase)
}

func TestInstallProcessTerminationAtDurableBoundaries(t *testing.T) {
	for _, phase := range []string{"pending", "executing", "executor", "committed", "final"} {
		t.Run(phase, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			installDir := filepath.Join(stateDir, "install")
			preparePreviousInstallation(t, installDir)
			childPhase := phase
			if phase == "executor" { childPhase = "executor" }
			cmd := exec.Command(os.Args[0], "-test.run=^TestInstallCrashHelper$")
			cmd.Env = append(os.Environ(),
				"WEDECENT_TEST_INSTALL_CRASH_PHASE="+childPhase,
				"WEDECENT_TEST_INSTALL_STATE_DIR="+stateDir,
			)
			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok { t.Fatalf("child error = %v, want process termination", err) }
			wantExit := 77
			if phase == "executor" { wantExit = 78 }
			if exitErr.ExitCode() != wantExit { t.Fatalf("child exit = %d, want %d", exitErr.ExitCode(), wantExit) }

			store := NewStateStore(StatePath(stateDir))
			state, err := store.Load()
			if err != nil { t.Fatal(err) }
			backupRoot := filepath.Join(stateDir, "install-transactions", "v0.4.0")
			executor := filesystemInstallerExecutor{root: installDir, backupRoot: backupRoot, statePath: store.Path}
			if phase == "final" {
				if state.PendingInstall != nil || state.StableSequence != 90 || !executor.verifyPrevious(InstallTransaction{PreviousVersion:"v0.0.0"}) && strings.TrimSpace(string(mustReadTestFile(filepath.Join(installDir, "version.txt")))) != "v0.4.0" {
					t.Fatalf("final transaction state = %#v", state)
				}
				if _, err := os.Stat(backupRoot); !errors.Is(err, os.ErrNotExist) { t.Fatalf("backup remains after durable finalization: %v", err) }
				return
			}
			if state.PendingInstall == nil || state.StableSequence != 0 {
				t.Fatalf("crash did not preserve pending journal without advancing sequence: %#v", state)
			}
			if phase == "executor" {
				if _, err := os.Stat(backupRoot); err != nil { t.Fatalf("transaction backup missing after interrupted replacement: %v", err) }
			}
			if err := store.RecoverPendingInstall(context.Background(), executor); err != nil { t.Fatalf("recover interrupted filesystem transaction: %v", err) }
			state, err = store.Load()
			if err != nil { t.Fatal(err) }
			if state.PendingInstall != nil || state.StableSequence != 0 { t.Fatalf("rollback state = %#v", state) }
			if !executor.verifyPrevious(InstallTransaction{PreviousVersion:"v0.0.0"}) { t.Fatal("previous installation was not restored and verified") }
			if _, err := os.Stat(backupRoot); !errors.Is(err, os.ErrNotExist) { t.Fatalf("backup not finalized after verified rollback: %v", err) }
		})
	}
}


func TestApplyVerifiedManifestRejectsStaleInstalledVersionUnderLock(t *testing.T) {
	manifest, archive := buildInstallerPackageFixture(t, nil)
	manifest.Sequence = 91
	staged := writeStagedArchive(t, archive)
	store := NewStateStore(StatePath(privateTempDir(t)))
	verified := testVerifiedUpdate(t, store, manifest, archive, 0)
	state, err := store.Load()
	if err != nil { t.Fatal(err) }
	state.InstalledVersion = "v0.1.0"
	if err := saveState(store.Path, state); err != nil { t.Fatal(err) }

	called := false
	err = store.applyVerifiedManifest(context.Background(), verified, staged, 0,
		func(context.Context, string) error { return nil },
		InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
			called = true
			return nil
		}))
	if !errors.Is(err, ErrRollback) || called {
		t.Fatalf("stale installed version error=%v executor_called=%v", err, called)
	}
	state, err = store.Load()
	if err != nil { t.Fatal(err) }
	if state.StableSequence != 0 || state.PendingInstall != nil {
		t.Fatalf("stale capability changed protected state: %#v", state)
	}
}

package updateinfo

import (
	"context"
	"errors"
	"fmt"
	"os"
)

var (
	ErrInstallerApply       = errors.New("updateinfo: installer application failed")
	ErrSequenceCommit       = errors.New("updateinfo: update installed but sequence commit failed")
	ErrInstallerUnavailable = errors.New("updateinfo: installer executor is required")
	ErrInstallRecoveryRequired = errors.New("updateinfo: interrupted installation requires recovery")
)

type InstallerExecutor interface {
	Execute(context.Context, VerifiedInstallerPackage) error
}

type InstallerExecutorFunc func(context.Context, VerifiedInstallerPackage) error

func (f InstallerExecutorFunc) Execute(ctx context.Context, pkg VerifiedInstallerPackage) error {
	if f == nil { return ErrInstallerUnavailable }
	return f(ctx, pkg)
}

// ApplyVerifiedInstaller is retained as a fail-closed compatibility shim.
// A plain Manifest is not proof of update authorization.
func (s *StateStore) ApplyVerifiedInstaller(_ context.Context, _ Manifest, _ string, _ int64, _ AuthenticodeVerifier, _ InstallerExecutor) error {
	return ErrUnverifiedManifest
}

// ApplyVerifiedInstallerForKeyset is retained as a fail-closed compatibility
// shim. Caller-supplied epoch equality cannot authenticate a manifest signer.
func (s *StateStore) ApplyVerifiedInstallerForKeyset(_ context.Context, _ Manifest, _ string, _ int64, _ AuthenticodeVerifier, _ InstallerExecutor, _ uint64) error {
	return ErrUnverifiedManifest
}

// ApplyVerifiedManifest is the sole installer admission boundary. The opaque
// capability binds signer identity, keyset epoch/digest and exact manifest bytes.
func (s *StateStore) ApplyVerifiedManifest(ctx context.Context, verified VerifiedManifest, stagedPath string, maxArchiveBytes int64, verifyAuthenticode AuthenticodeVerifier, executor InstallerExecutor) error {
	if s == nil || s.Path == "" { return fmt.Errorf("%w: state path is required", ErrInvalidState) }
	if err := verified.validate(); err != nil { return err }
	if executor == nil { return ErrInstallerUnavailable }
	if verifyAuthenticode == nil { return fmt.Errorf("%w: Authenticode policy is required", ErrInstallerPackage) }
	if ctx == nil { return fmt.Errorf("%w: context is required", ErrInvalidState) }
	if err := ctx.Err(); err != nil { return err }

	manifest := verified.manifest
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := acquireUpdateLock(ctx, s.Path)
	if err != nil { return err }
	defer release()

	current, err := loadState(s.Path)
	if err != nil { return err }
	if current.PendingInstall != nil { return ErrInstallRecoveryRequired }
	if current.KeysetEpoch != verified.keysetEpoch || current.KeysetDigest != verified.keysetDigest {
		return fmt.Errorf("%w: verified signer keyset is no longer current", ErrKeysetRollback)
	}
	if manifest.Sequence <= current.StableSequence {
		return fmt.Errorf("%w: sequence %d is not newer than %d", ErrRollback, manifest.Sequence, current.StableSequence)
	}

	mutated := false
	err = WithVerifiedInstallerPackage(ctx, manifest, stagedPath, maxArchiveBytes, verifyAuthenticode,
		func(_ context.Context, pkg VerifiedInstallerPackage) error {
			if err := ctx.Err(); err != nil { return err }
			transaction, err := newInstallTransaction(verified, pkg)
			if err != nil { return err }
			pendingState := current
			pendingState.PendingInstall = &transaction
			if err := saveState(s.Path, pendingState); err != nil { return fmt.Errorf("%w: persist pending install intent", ErrInvalidState) }
			mutated = true
			if err := executor.Execute(context.WithoutCancel(ctx), pkg); err != nil { return ErrInstallerApply }
			return nil
		})
	if err != nil { return err }
	if !mutated { return fmt.Errorf("%w: installer executor was not invoked", ErrInstallerApply) }

	nextState := State{Version: UpdateStateVersionWithKeyset, StableSequence: manifest.Sequence, KeysetEpoch: current.KeysetEpoch, KeysetDigest: current.KeysetDigest}
	if err := saveState(s.Path, nextState); err != nil { return ErrSequenceCommit }
	return nil
}

// ApplyStable is the supported orchestration path. Cryptographic authority
// remains in updateinfo/Local Core, never in the desktop presentation layer.
func (c DiscoveryClient) ApplyStable(ctx context.Context, currentVersion string, highestSequence uint64, installerClient InstallerClient, stagingDir string, maxArchiveBytes int64, verifyAuthenticode AuthenticodeVerifier, executor InstallerExecutor) (Manifest, error) {
	var zero Manifest
	if c.State == nil { return zero, fmt.Errorf("%w: protected update state is required", ErrDiscovery) }
	if verifyAuthenticode == nil { return zero, fmt.Errorf("%w: Authenticode policy is required", ErrInstallerPackage) }
	if executor == nil { return zero, ErrInstallerUnavailable }
	verified, err := c.DiscoverStableVerified(ctx, currentVersion, highestSequence)
	if err != nil { return zero, err }
	manifest := verified.Manifest()
	if installerClient.Transport == nil { installerClient.Transport = c.Transport }
	staged, err := installerClient.Stage(ctx, manifest, stagingDir)
	if err != nil { return zero, err }
	defer os.Remove(staged.Path)
	if err := c.State.ApplyVerifiedManifest(ctx, verified, staged.Path, maxArchiveBytes, verifyAuthenticode, executor); err != nil { return zero, err }
	return manifest, nil
}

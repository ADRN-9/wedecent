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
)

// InstallerExecutor is the privileged mutation boundary. Execute is called only
// while pkg.Dir is inside the verified-package callback and therefore still
// exists. Implementations must not retain paths from pkg after returning.
type InstallerExecutor interface {
	Execute(context.Context, VerifiedInstallerPackage) error
}

// InstallerExecutorFunc adapts a function to InstallerExecutor.
type InstallerExecutorFunc func(context.Context, VerifiedInstallerPackage) error

func (f InstallerExecutorFunc) Execute(ctx context.Context, pkg VerifiedInstallerPackage) error {
	if f == nil {
		return ErrInstallerUnavailable
	}
	return f(ctx, pkg)
}

// ApplyVerifiedInstaller verifies and applies one signed stable-channel update,
// then commits its anti-rollback sequence only after the installer reports
// success. Both the StateStore mutex and a protected OS file lock span rollback
// admission through sequence commit, so independent updater processes cannot
// both admit the same sequence.
//
// Cancellation is honored until mutation starts. Once Execute begins, its
// context is detached from caller cancellation so the installer transaction is
// allowed to reach a known success/failure outcome instead of being abandoned
// mid-rollback. The caller still receives a stable installer-failure class, but
// raw privileged-process errors are deliberately not exposed.
func (s *StateStore) ApplyVerifiedInstaller(
	ctx context.Context,
	manifest Manifest,
	stagedPath string,
	maxArchiveBytes int64,
	verifyAuthenticode AuthenticodeVerifier,
	executor InstallerExecutor,
) error {
	return s.applyVerifiedInstaller(ctx, manifest, stagedPath, maxArchiveBytes, verifyAuthenticode, executor, nil)
}

// ApplyVerifiedInstallerForKeyset binds installation to the keyset epoch used
// during discovery. The epoch is checked under the same cross-process lock that
// admits and commits the stable sequence, preventing a concurrent keyset rotation
// from invalidating the signer between discovery and installation.
func (s *StateStore) ApplyVerifiedInstallerForKeyset(
	ctx context.Context,
	manifest Manifest,
	stagedPath string,
	maxArchiveBytes int64,
	verifyAuthenticode AuthenticodeVerifier,
	executor InstallerExecutor,
	expectedKeysetEpoch uint64,
) error {
	if expectedKeysetEpoch == 0 || manifest.Schema != ManifestSchemaV2 || manifest.KeysetEpoch != expectedKeysetEpoch {
		return fmt.Errorf("%w: manifest and expected keyset epoch must match", ErrInvalidState)
	}
	return s.applyVerifiedInstaller(ctx, manifest, stagedPath, maxArchiveBytes, verifyAuthenticode, executor, &expectedKeysetEpoch)
}

func (s *StateStore) applyVerifiedInstaller(
	ctx context.Context,
	manifest Manifest,
	stagedPath string,
	maxArchiveBytes int64,
	verifyAuthenticode AuthenticodeVerifier,
	executor InstallerExecutor,
	expectedKeysetEpoch *uint64,
) error {
	if s == nil || s.Path == "" {
		return fmt.Errorf("%w: state path is required", ErrInvalidState)
	}
	if executor == nil {
		return ErrInstallerUnavailable
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := acquireUpdateLock(ctx, s.Path)
	if err != nil {
		return err
	}
	defer release()

	current, err := loadState(s.Path)
	if err != nil {
		return err
	}
	if manifest.Sequence <= current.StableSequence {
		return fmt.Errorf("%w: sequence %d is not newer than %d", ErrRollback, manifest.Sequence, current.StableSequence)
	}
	if expectedKeysetEpoch != nil && current.KeysetEpoch != *expectedKeysetEpoch {
		return fmt.Errorf("%w: persisted keyset epoch changed before installation", ErrKeysetRollback)
	}

	mutated := false
	err = WithVerifiedInstallerPackage(
		ctx,
		manifest,
		stagedPath,
		maxArchiveBytes,
		verifyAuthenticode,
		func(_ context.Context, pkg VerifiedInstallerPackage) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			mutated = true
			if err := executor.Execute(context.WithoutCancel(ctx), pkg); err != nil {
				return ErrInstallerApply
			}
			return nil
		},
	)
	if err != nil {
		return err
	}
	if !mutated {
		return fmt.Errorf("%w: installer executor was not invoked", ErrInstallerApply)
	}

	nextState := State{
		Version:        current.Version,
		StableSequence: manifest.Sequence,
		KeysetEpoch:    current.KeysetEpoch,
		KeysetDigest:   current.KeysetDigest,
	}
	if nextState.Version == 0 {
		nextState.Version = UpdateStateVersion
	}
	if err := saveState(s.Path, nextState); err != nil {
		return ErrSequenceCommit
	}
	return nil
}

// ApplyStable performs the complete verified stable-channel update transaction:
// discover and authenticate the v2 manifest/keyset, stage the immutable archive,
// re-verify the package and Authenticode policy, execute the installer, then
// commit the sequence only after successful installation. The caller must supply
// a provisioned root pin, protected StateStore, platform Authenticode policy,
// and an executor running in the required trusted privilege context.
func (c DiscoveryClient) ApplyStable(
	ctx context.Context,
	currentVersion string,
	highestSequence uint64,
	installerClient InstallerClient,
	stagingDir string,
	maxArchiveBytes int64,
	verifyAuthenticode AuthenticodeVerifier,
	executor InstallerExecutor,
) (Manifest, error) {
	var zero Manifest
	if c.State == nil {
		return zero, fmt.Errorf("%w: protected update state is required", ErrDiscovery)
	}
	if verifyAuthenticode == nil {
		return zero, fmt.Errorf("%w: Authenticode policy is required", ErrInstallerPackage)
	}
	if executor == nil {
		return zero, ErrInstallerUnavailable
	}
	manifest, err := c.DiscoverStable(ctx, currentVersion, highestSequence)
	if err != nil {
		return zero, err
	}
	if installerClient.Transport == nil {
		installerClient.Transport = c.Transport
	}
	staged, err := installerClient.Stage(ctx, manifest, stagingDir)
	if err != nil {
		return zero, err
	}
	defer os.Remove(staged.Path)
	if err := c.State.ApplyVerifiedInstallerForKeyset(
		ctx, manifest, staged.Path, maxArchiveBytes, verifyAuthenticode, executor, manifest.KeysetEpoch,
	); err != nil {
		return zero, err
	}
	return manifest, nil
}

package updateinfo

import (
	"context"
	"errors"
	"fmt"
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

	if err := saveState(s.Path, State{Version: UpdateStateVersion, StableSequence: manifest.Sequence}); err != nil {
		return ErrSequenceCommit
	}
	return nil
}

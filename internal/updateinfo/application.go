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
	ErrInstallCleanupPending = errors.New("updateinfo: update committed; transaction backup cleanup pending")
	ErrInstallerUnavailable = errors.New("updateinfo: installer executor is required")
)

// InstallerExecutor is the privileged mutation boundary. It receives the
// durable transaction ID so the service can reject replay and bind replacement
// to the verified package. It must keep the previous valid installation as a
// recoverable backup until the target is independently confirmed.
type InstallerExecutor interface {
	Execute(context.Context, InstallTransaction, VerifiedInstallerPackage) error
}

type InstallerExecutorFunc func(context.Context, InstallTransaction, VerifiedInstallerPackage) error

func (f InstallerExecutorFunc) Execute(ctx context.Context, transaction InstallTransaction, pkg VerifiedInstallerPackage) error {
	if f == nil {
		return ErrInstallerUnavailable
	}
	return f(ctx, transaction, pkg)
}

func (s *StateStore) finalizeCommittedInstalls(ctx context.Context, finalizer InstallerCommitFinalizer) error {
	if s == nil || s.Path == "" || ctx == nil || finalizer == nil {
		return ErrInstallCleanupPending
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := acquireUpdateLock(ctx, s.Path)
	if err != nil {
		return err
	}
	defer release()
	state, err := loadState(s.Path)
	if err != nil {
		return err
	}
	if state.PendingInstall != nil {
		return ErrInstallRecoveryRequired
	}
	return finalizer.FinalizeCommitted(ctx, state)
}

func (s *StateStore) applyVerifiedManifest(
	ctx context.Context,
	verified VerifiedManifest,
	stagedPath string,
	maxArchiveBytes int64,
	verifyAuthenticode AuthenticodeVerifier,
	executor InstallerExecutor,
) error {
	if s == nil || s.Path == "" {
		return fmt.Errorf("%w: state path is required", ErrInvalidState)
	}
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidState)
	}
	if executor == nil {
		return ErrInstallerUnavailable
	}
	if err := verified.validate(); err != nil {
		return err
	}
	if verifyAuthenticode == nil {
		return fmt.Errorf("%w: Authenticode policy is required", ErrInstallerPackage)
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
	if current.PendingInstall != nil {
		return ErrInstallRecoveryRequired
	}
	if current.InstalledVersion == "" || current.InstalledVersion != verified.previousVersion {
		return fmt.Errorf("%w: protected installed version changed or is unavailable", ErrRollback)
	}
	if current.KeysetEpoch != verified.keysetEpoch || current.KeysetDigest != verified.keysetDigest {
		return fmt.Errorf("%w: verified manifest keyset is stale or revoked", ErrKeysetRollback)
	}
	if verified.manifest.Sequence <= current.StableSequence {
		return fmt.Errorf("%w: sequence %d is not newer than %d", ErrRollback, verified.manifest.Sequence, current.StableSequence)
	}
	if verified.highestSequence > current.StableSequence {
		return fmt.Errorf("%w: capability sequence baseline is inconsistent", ErrRollback)
	}

	return WithVerifiedInstallerPackage(
		ctx, verified.manifest, stagedPath, maxArchiveBytes, verifyAuthenticode,
		func(_ context.Context, pkg VerifiedInstallerPackage) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			transaction, err := newInstallTransaction(verified, pkg)
			if err != nil {
				return err
			}

			pending := current
			pending.Version = UpdateStateVersionWithInstall
			pending.PendingInstall = &transaction
			if err := s.persistInstallTransition(current, pending); err != nil {
				return fmt.Errorf("%w: persist pending installer intent", ErrInvalidState)
			}

			executing := pending
			executingTransaction := transaction
			executingTransaction.Phase = InstallPhaseExecuting
			executing.PendingInstall = &executingTransaction
			if err := s.persistInstallTransition(pending, executing); err != nil {
				return fmt.Errorf("%w: persist executing installer state", ErrInvalidState)
			}
			if err := executor.Execute(context.WithoutCancel(ctx), executingTransaction, pkg); err != nil {
				recoveryRequired := executing
				recoveryTransaction := executingTransaction
				recoveryTransaction.Phase = InstallPhaseRecoveryRequired
				recoveryRequired.PendingInstall = &recoveryTransaction
				_ = s.persistInstallTransition(executing, recoveryRequired)
				return ErrInstallerApply
			}

			committed := executing
			committedTransaction := executingTransaction
			committedTransaction.Phase = InstallPhaseCommitted
			committed.PendingInstall = &committedTransaction
			if err := s.persistInstallTransition(executing, committed); err != nil {
				return ErrSequenceCommit
			}
			next := committed
			next.StableSequence = verified.manifest.Sequence
			next.InstalledVersion = transaction.TargetVersion
			next.PendingInstall = nil
			if err := s.persistInstallTransition(committed, next); err != nil {
				return ErrSequenceCommit
			}
			if finalizer, ok := executor.(InstallerCommitFinalizer); ok {
				if err := finalizer.FinalizeCommitted(context.WithoutCancel(ctx), next); err != nil {
					return fmt.Errorf("%w: %v", ErrInstallCleanupPending, err)
				}
			}
			return nil
		},
	)
}

// RecoverPendingInstall reconciles an interrupted installer under the same
// cross-process lock used by admission. Unknown outcomes retain the journal and
// block subsequent updates. Recovery adapters must be idempotent and preserve
// the last known-good backup until target verification succeeds.
func (s *StateStore) RecoverPendingInstall(ctx context.Context, recovery InstallerRecovery) error {
	if s == nil || s.Path == "" || ctx == nil || recovery == nil {
		return ErrInstallRecoveryRequired
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
	if current.PendingInstall == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	transaction := *current.PendingInstall
	recoveryState := current
	transaction.Phase = InstallPhaseRecoveryRequired
	recoveryState.PendingInstall = &transaction
	if err := s.persistInstallTransition(current, recoveryState); err != nil {
		return ErrInstallRecoveryRequired
	}

	result, err := recovery.Recover(context.WithoutCancel(ctx), transaction)
	if err != nil || result == InstallRecoveryUnknown {
		return ErrInstallRecoveryRequired
	}

	next := recoveryState
	switch result {
	case InstallRecoveryApplied:
		if transaction.Sequence <= recoveryState.StableSequence {
			return ErrInstallRecoveryRequired
		}
		next.StableSequence = transaction.Sequence
		next.InstalledVersion = transaction.TargetVersion
	case InstallRecoveryNotApplied:
		// Adapter has verified restoration of PreviousVersion; sequence stays unchanged.
	default:
		return ErrInstallRecoveryRequired
	}
	next.PendingInstall = nil
	if err := s.persistInstallTransition(recoveryState, next); err != nil {
		return ErrInstallRecoveryRequired
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
	if recovery, ok := executor.(InstallerRecovery); ok {
		if err := c.State.RecoverPendingInstall(ctx, recovery); err != nil {
			return zero, err
		}
	}
	if finalizer, ok := executor.(InstallerCommitFinalizer); ok {
		if err := c.State.finalizeCommittedInstalls(ctx, finalizer); err != nil {
			return zero, fmt.Errorf("%w: %v", ErrInstallCleanupPending, err)
		}
	}
	verified, err := c.DiscoverStableVerified(ctx, currentVersion, highestSequence)
	if err != nil {
		return zero, err
	}
	manifest := verified.Manifest()
	if installerClient.Transport == nil {
		installerClient.Transport = c.Transport
	}
	staged, err := installerClient.Stage(ctx, manifest, stagingDir)
	if err != nil {
		return zero, err
	}
	defer os.Remove(staged.Path)
	if err := c.State.applyVerifiedManifest(
		ctx, verified, staged.Path, maxArchiveBytes, verifyAuthenticode, executor,
	); err != nil {
		return zero, err
	}
	return manifest, nil
}

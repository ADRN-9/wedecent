package updateinfo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var ErrInstallTransaction = errors.New("updateinfo: invalid installer transaction")

type InstallTransaction struct {
	ID              string
	Sequence        uint64
	ManifestDigest  string
	PackageDigest   string
	PreviousVersion string
	TargetVersion   string
	RecoveryState   string
}

func (t InstallTransaction) validate() error {
	if len(t.ID) != 32 || t.Sequence == 0 ||
		len(t.ManifestDigest) != 64 || len(t.PackageDigest) != 64 ||
		t.PreviousVersion == "" || t.TargetVersion == "" ||
		t.PreviousVersion == t.TargetVersion ||
		(t.RecoveryState != "pending" && t.RecoveryState != "recovery-required") {
		return ErrInstallTransaction
	}
	for _, value := range []string{t.ID, t.ManifestDigest, t.PackageDigest} {
		if strings.ToLower(value) != value {
			return ErrInstallTransaction
		}
		if _, err := hex.DecodeString(value); err != nil {
			return ErrInstallTransaction
		}
	}
	if _, err := parseStableVersion(t.PreviousVersion); err != nil {
		return ErrInstallTransaction
	}
	if _, err := parseStableVersion(t.TargetVersion); err != nil {
		return ErrInstallTransaction
	}
	return nil
}

func newInstallTransaction(verified VerifiedManifest, _ VerifiedInstallerPackage) (InstallTransaction, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return InstallTransaction{}, fmt.Errorf("%w: transaction ID generation failed", ErrInstallTransaction)
	}
	transaction := InstallTransaction{
		ID:              hex.EncodeToString(raw[:]),
		Sequence:        verified.manifest.Sequence,
		ManifestDigest:  verified.manifestDigest,
		PackageDigest:   verified.manifest.InstallerSHA256,
		PreviousVersion: verified.previousVersion,
		TargetVersion:   verified.manifest.Version,
		RecoveryState:   "pending",
	}
	if err := transaction.validate(); err != nil {
		return InstallTransaction{}, err
	}
	return transaction, nil
}

type InstallRecoveryResult uint8

const (
	InstallRecoveryUnknown InstallRecoveryResult = iota
	InstallRecoveryNotApplied
	InstallRecoveryApplied
)

type InstallerRecovery interface {
	Recover(context.Context, InstallTransaction) (InstallRecoveryResult, error)
}

// RecoverPendingInstall reconciles an interrupted mutation under the same
// cross-process lock as admission. Unknown outcomes remain blocked.
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
	pending := *current.PendingInstall
	pending.RecoveryState = "recovery-required"
	current.PendingInstall = &pending
	if err := saveState(s.Path, current); err != nil {
		return ErrInstallRecoveryRequired
	}
	result, err := recovery.Recover(context.WithoutCancel(ctx), pending)
	if err != nil || result == InstallRecoveryUnknown {
		return ErrInstallRecoveryRequired
	}
	next := current
	transaction := *current.PendingInstall
	switch result {
	case InstallRecoveryApplied:
		if transaction.Sequence <= current.StableSequence {
			return ErrInstallRecoveryRequired
		}
		next.StableSequence = transaction.Sequence
	case InstallRecoveryNotApplied:
		// The recovery adapter confirms rollback/repair to the previous version.
	default:
		return ErrInstallRecoveryRequired
	}
	next.PendingInstall = nil
	if err := saveState(s.Path, next); err != nil {
		return ErrInstallRecoveryRequired
	}
	return nil
}

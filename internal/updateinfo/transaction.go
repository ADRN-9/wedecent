package updateinfo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var ErrInstallRecoveryRequired = errors.New("updateinfo: interrupted installation requires recovery")
var ErrInstallTransaction = errors.New("updateinfo: invalid installation transaction")

const (
	InstallPhasePending          = "pending"
	InstallPhaseExecuting        = "executing"
	InstallPhaseCommitted        = "committed"
	InstallPhaseRecoveryRequired = "recovery-required"
)

type InstallTransaction struct {
	ID              string `json:"id"`
	Sequence        uint64 `json:"sequence"`
	ManifestDigest  string `json:"manifest_digest"`
	PackageDigest   string `json:"package_digest"`
	PreviousVersion string `json:"previous_version"`
	TargetVersion   string `json:"target_version"`
	Phase           string `json:"phase"`
}

func (t InstallTransaction) validate() error {
	if len(t.ID) != 32 || t.Sequence == 0 || len(t.ManifestDigest) != 64 || len(t.PackageDigest) != 64 || t.PreviousVersion == "" || t.TargetVersion == "" || t.PreviousVersion == t.TargetVersion {
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
	switch t.Phase {
	case InstallPhasePending, InstallPhaseExecuting, InstallPhaseCommitted, InstallPhaseRecoveryRequired:
	default:
		return ErrInstallTransaction
	}
	return nil
}

func newInstallTransaction(verified VerifiedManifest, pkg VerifiedInstallerPackage) (InstallTransaction, error) {
	if err := verified.validate(); err != nil {
		return InstallTransaction{}, err
	}
	if pkg.Version != verified.manifest.Version {
		return InstallTransaction{}, ErrInstallTransaction
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return InstallTransaction{}, fmt.Errorf("%w: transaction ID generation failed", ErrInstallTransaction)
	}
	t := InstallTransaction{ID: hex.EncodeToString(raw[:]), Sequence: verified.manifest.Sequence, ManifestDigest: verified.manifestDigest, PackageDigest: verified.manifest.InstallerSHA256, PreviousVersion: verified.previousVersion, TargetVersion: verified.manifest.Version, Phase: InstallPhasePending}
	if err := t.validate(); err != nil {
		return InstallTransaction{}, err
	}
	return t, nil
}

type InstallRecoveryResult uint8

const (
	InstallRecoveryUnknown InstallRecoveryResult = iota
	InstallRecoveryNotApplied
	InstallRecoveryApplied
)

// InstallerRecovery must be idempotent. Applied is returned only after the target version and package identity are verified. NotApplied is returned only after the previous working version is restored and verified. It must retain the last valid backup until a replacement is independently confirmed.
type InstallerRecovery interface {
	Recover(context.Context, InstallTransaction) (InstallRecoveryResult, error)
}

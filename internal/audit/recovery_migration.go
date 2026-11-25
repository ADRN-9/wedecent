package audit

import (
	"context"
	"crypto/sha256"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"wedecent.com/wedecent/internal/trust"
)

const maxLegacyRecoveryMigrationProofBytes = 64 << 10

// MigrateLegacyArchive attaches independent authority to an existing local-MAC
// archive only when an out-of-band authenticated checkpoint is supplied. The
// authority must durably deduplicate MigrationOperationID across retries.
func (r *PairingRecovery) MigrateLegacyArchive(ctx context.Context, authenticatedCheckpoint []byte) error {
	if r == nil || r.authority == nil || ctx == nil {
		return ErrRecoveryAuthorityUnavailable
	}
	if len(authenticatedCheckpoint) == 0 || len(authenticatedCheckpoint) > maxLegacyRecoveryMigrationProofBytes {
		return ErrRecoveryMigrationUntrusted
	}
	if err := r.authorityTrust.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := trust.VerifyPairingStatePath(filepath.Dir(r.path)); err != nil {
		return err
	}
	unlock, err := lockFile(r.path)
	if err != nil {
		return err
	}
	defer unlock()

	archivePath := filepath.Join(filepath.Dir(r.path), pairingArchiveFileName)
	info, err := os.Lstat(archivePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrRecoveryMigrationUntrusted
		}
		return err
	}
	if err := trust.VerifyPairingStatePath(archivePath); err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPairingArchiveBytes {
		return ErrRecoveryMigrationUntrusted
	}
	legacyBytes, err := os.ReadFile(archivePath)
	if err != nil || len(legacyBytes) == 0 || len(legacyBytes) > maxPairingArchiveBytes {
		return ErrRecoveryMigrationUntrusted
	}
	legacyReader := *r
	legacyReader.authority = nil
	legacyArchive, err := legacyReader.readArchive()
	if err != nil {
		return fmt.Errorf("%w: legacy archive authentication failed: %v", ErrRecoveryMigrationUntrusted, err)
	}
	if legacyArchive.AuthorityGeneration != 0 || legacyArchive.AuthorityKeyID != "" ||
		legacyArchive.AuthoritySignature != "" || legacyArchive.AuthorityCheckpoint.Generation != 0 {
		if err := r.verifyIndependentArchive(ctx, legacyArchive, mustMarshalArchivePayload(legacyArchive)); err != nil {
			return err
		}
		return nil
	}
	head, err := r.authority.LoadCheckpoint(ctx, r.authorityScope)
	if err != nil {
		return fmt.Errorf("%w: load migration authority head: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	if head.Scope != r.authorityScope {
		return ErrRecoveryCheckpointConflict
	}
	if head.Generation > 0 {
		if err := r.verifyAuthorityCheckpoint(ctx, head); err != nil {
			return err
		}
	}
	archiveDigest := sha256.Sum256(legacyBytes)
	operationMaterial, err := json.Marshal(struct {
		Domain     string   `json:"domain"`
		Scope      string   `json:"scope"`
		Archive    string   `json:"archive"`
		Generation uint64   `json:"generation"`
	}{Domain: "wedecent-pairing-recovery-legacy-migration-v1", Scope: r.authorityScope,
		Archive: hex.EncodeToString(archiveDigest[:]), Generation: head.Generation})
	if err != nil {
		return err
	}
	operationDigest := sha256.Sum256(operationMaterial)
	migration := LegacyRecoveryMigrationRequest{Scope: r.authorityScope, LegacyArchiveSHA256: archiveDigest,
		ExpectedGeneration: head.Generation, AuthenticatedCheckpoint: append([]byte(nil), authenticatedCheckpoint...),
		MigrationOperationID: hex.EncodeToString(operationDigest[:])}
	checkpoint, err := r.authority.MigrateLegacyArchive(ctx, migration)
	if err != nil {
		if errors.Is(err, ErrRecoveryMigrationUntrusted) || errors.Is(err, ErrRecoveryCheckpointStale) ||
			errors.Is(err, ErrRecoveryCheckpointConflict) {
			return err
		}
		return fmt.Errorf("%w: legacy migration result requires exact retry/reconciliation: %v", ErrRecoveryCommitUncertain, err)
	}
	if checkpoint.Scope != r.authorityScope || checkpoint.Generation != head.Generation+1 ||
		checkpoint.PreviousDigest != head.StateDigest {
		return ErrRecoveryCheckpointConflict
	}
	localCheckpoint, err := pairingArchiveCheckpoint(legacyArchive.Records)
	if err != nil || localCheckpoint != legacyArchive.Checkpoint {
		return ErrRecoveryMigrationUntrusted
	}
	unsigned := pairingRecoveryArchiveUnsigned{Version: legacyArchive.Version, FirstSequence: legacyArchive.FirstSequence,
		LastSequence: legacyArchive.LastSequence, Checkpoint: legacyArchive.Checkpoint, Records: legacyArchive.Records,
		AuthorityGeneration: checkpoint.Generation, AuthorityPreviousDigest: hex.EncodeToString(checkpoint.PreviousDigest[:])}
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	stateDigest := sha256.Sum256(payload)
	request, err := NewRecoveryCheckpointRequest(r.authorityScope, head.Generation, head.StateDigest, stateDigest)
	if err != nil {
		return err
	}
	if checkpoint.StateDigest != stateDigest || checkpoint.OperationID != request.OperationID {
		return ErrRecoveryCheckpointConflict
	}
	if err := r.authority.VerifyCheckpoint(ctx, checkpoint); err != nil {
		return fmt.Errorf("%w: migrated checkpoint signature rejected: %v", ErrRecoveryCheckpointConflict, err)
	}
	if err := ValidateRecoveryCheckpointWithTrust(request, checkpoint, r.authorityTrust); err != nil {
		return err
	}
	keyID, signature, err := r.authority.SignArchive(ctx, payload)
	if err != nil {
		return fmt.Errorf("%w: sign migrated archive: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	if keyID == "" || len(signature) != 64 {
		return ErrRecoveryCheckpointConflict
	}
	if err := r.authority.VerifyArchive(ctx, keyID, payload, signature); err != nil {
		return fmt.Errorf("%w: migrated archive signature rejected: %v", ErrRecoveryCheckpointConflict, err)
	}
	migrated := legacyArchive
	migrated.AuthorityGeneration = checkpoint.Generation
	migrated.AuthorityPreviousDigest = hex.EncodeToString(checkpoint.PreviousDigest[:])
	migrated.AuthorityKeyID = keyID
	migrated.AuthoritySignature = hex.EncodeToString(signature)
	migrated.AuthorityCheckpoint = checkpoint
	localMAC := hmacSHA256(r.archiveKey, payload)
	migrated.MAC = hex.EncodeToString(localMAC)
	data, err := json.Marshal(migrated)
	if err != nil || len(data) == 0 || len(data) > maxPairingArchiveBytes {
		return ErrRecoveryMigrationUntrusted
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.path), ".pairing-recovery-migration-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := trust.VerifyPairingStatePath(name); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceAuditArchive(name, archivePath); err != nil {
		return fmt.Errorf("%w: migration publication uncertain: %v", ErrRecoveryCommitUncertain, err)
	}
	if err := syncAuditDirectory(filepath.Dir(r.path)); err != nil {
		return fmt.Errorf("%w: migration directory sync uncertain: %v", ErrRecoveryCommitUncertain, err)
	}
	verified, err := r.readArchive()
	if err != nil || !sameRecoveryCheckpoint(verified.AuthorityCheckpoint, checkpoint) {
		return fmt.Errorf("%w: migrated archive did not verify after publication: %v", ErrRecoveryCommitUncertain, err)
	}
	return nil
}

func mustMarshalArchivePayload(archive pairingRecoveryArchive) []byte {
	unsigned := pairingRecoveryArchiveUnsigned{Version: archive.Version, FirstSequence: archive.FirstSequence,
		LastSequence: archive.LastSequence, Checkpoint: archive.Checkpoint, Records: archive.Records,
		AuthorityGeneration: archive.AuthorityGeneration, AuthorityPreviousDigest: archive.AuthorityPreviousDigest}
	payload, _ := json.Marshal(unsigned)
	return payload
}

func hmacSHA256(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}


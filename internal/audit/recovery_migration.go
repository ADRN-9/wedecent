package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return ErrRecoveryMigrationUntrusted
	}
	opened, statErr := archiveFile.Stat()
	after, pathErr := os.Lstat(archivePath)
	if statErr != nil || pathErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, after) {
		_ = archiveFile.Close()
		return ErrRecoveryMigrationUntrusted
	}
	legacyBytes, readErr := io.ReadAll(io.LimitReader(archiveFile, maxPairingArchiveBytes+1))
	closeErr := archiveFile.Close()
	if readErr != nil || closeErr != nil || len(legacyBytes) == 0 || len(legacyBytes) > maxPairingArchiveBytes {
		return ErrRecoveryMigrationUntrusted
	}
	legacyReader := &PairingRecovery{path: r.path, archiveKey: r.archiveKey}
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
	if head.Scope != r.authorityScope || (head.Generation == 0 && !emptyRecoveryCheckpoint(head)) {
		return ErrRecoveryCheckpointConflict
	}
	if head.Generation > 0 {
		if err := r.verifyAuthorityCheckpoint(ctx, head); err != nil {
			return err
		}
	}
	archiveDigest := sha256.Sum256(legacyBytes)
	operationMaterial, err := json.Marshal(struct {
		Domain  string `json:"domain"`
		Scope   string `json:"scope"`
		Archive string `json:"archive"`
	}{Domain: "wedecent-pairing-recovery-legacy-migration-v1", Scope: r.authorityScope,
		Archive: hex.EncodeToString(archiveDigest[:])})
	if err != nil {
		return err
	}
	operationDigest := sha256.Sum256(operationMaterial)
	migration := LegacyRecoveryMigrationRequest{Scope: r.authorityScope, LegacyArchiveSHA256: archiveDigest,
		ExpectedGeneration: head.Generation, AuthenticatedCheckpoint: append([]byte(nil), authenticatedCheckpoint...),
		MigrationOperationID: hex.EncodeToString(operationDigest[:])}
	localCheckpoint, err := pairingArchiveCheckpoint(legacyArchive.Records)
	if err != nil || localCheckpoint != legacyArchive.Checkpoint {
		return ErrRecoveryMigrationUntrusted
	}
	build := func(generation uint64, previous [sha256.Size]byte) ([]byte, [sha256.Size]byte, error) {
		unsigned := pairingRecoveryArchiveUnsigned{Version: legacyArchive.Version, FirstSequence: legacyArchive.FirstSequence,
			LastSequence: legacyArchive.LastSequence, Checkpoint: legacyArchive.Checkpoint, Records: legacyArchive.Records,
			AuthorityGeneration: generation, AuthorityPreviousDigest: hex.EncodeToString(previous[:])}
		payload, marshalErr := json.Marshal(unsigned)
		if marshalErr != nil {
			return nil, [sha256.Size]byte{}, marshalErr
		}
		return payload, sha256.Sum256(payload), nil
	}
	var payload []byte
	var stateDigest [sha256.Size]byte
	var checkpoint RecoveryCheckpoint
	alreadyCommitted := false
	if head.Generation > 0 {
		payload, stateDigest, err = build(head.Generation, head.PreviousDigest)
		if err != nil {
			return err
		}
		if stateDigest == head.StateDigest {
			checkpoint = head
			alreadyCommitted = true
		}
	}
	if !alreadyCommitted {
		if head.Generation == ^uint64(0) {
			return ErrRecoveryCheckpointStale
		}
		payload, stateDigest, err = build(head.Generation+1, head.StateDigest)
		if err != nil {
			return err
		}
		request, requestErr := NewRecoveryCheckpointRequest(r.authorityScope, head.Generation, head.StateDigest, stateDigest)
		if requestErr != nil {
			return requestErr
		}
		checkpoint, err = r.authority.MigrateLegacyArchive(ctx, migration)
		if err != nil {
			if errors.Is(err, ErrRecoveryMigrationUntrusted) || errors.Is(err, ErrRecoveryCheckpointStale) ||
				errors.Is(err, ErrRecoveryCheckpointConflict) {
				return err
			}
			observed, loadErr := r.authority.LoadCheckpoint(ctx, r.authorityScope)
			if loadErr != nil || observed.Scope != request.Scope || observed.Generation != request.Generation ||
				observed.PreviousDigest != request.PreviousDigest || observed.StateDigest != request.StateDigest ||
				observed.OperationID != request.OperationID {
				return fmt.Errorf("%w: legacy migration result requires exact retry/reconciliation: %v", ErrRecoveryCommitUncertain, err)
			}
			checkpoint = observed
		}
		if checkpoint.Scope != r.authorityScope || checkpoint.Generation != request.Generation ||
			checkpoint.PreviousDigest != request.PreviousDigest || checkpoint.StateDigest != request.StateDigest ||
			checkpoint.OperationID != request.OperationID {
			return ErrRecoveryCheckpointConflict
		}
	}
	if err := verifyLegacyMigrationProofStateDigest(authenticatedCheckpoint, stateDigest); err != nil {
		return err
	}
	request, err := NewRecoveryCheckpointRequest(r.authorityScope, checkpoint.Generation-1, checkpoint.PreviousDigest, checkpoint.StateDigest)
	if err != nil || checkpoint.StateDigest != stateDigest || checkpoint.OperationID != request.OperationID {
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
	if keyID != recoveryPrimaryKeyID(r.authorityTrust.PrimaryKey) || len(signature) != 64 {
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
	r.migrationPending = false
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

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"wedecent.com/wedecent/internal/trust"
)

const activeLedgerAuthoritySuffix = "/active-ledger"

type pairingOutcomeSnapshotUnsigned struct {
	Version           int              `json:"version"`
	Records           []PairingOutcome `json:"records"`
	ArchivedThrough   uint64           `json:"archived_through,omitempty"`
	ArchiveCheckpoint string           `json:"archive_checkpoint,omitempty"`
}

type pairingOutcomeSnapshotPending struct {
	Unsigned  pairingOutcomeSnapshotUnsigned `json:"unsigned"`
	Request   RecoveryCheckpointRequest       `json:"request"`
	Migration *LegacyRecoveryMigrationRequest `json:"migration,omitempty"`
}

func (r *PairingRecovery) activeLedgerScope() string {
	return r.authorityScope + activeLedgerAuthoritySuffix
}

func unsignedPairingSnapshot(snapshot pairingOutcomeSnapshot) pairingOutcomeSnapshotUnsigned {
	return pairingOutcomeSnapshotUnsigned{Version: snapshot.Version, Records: snapshot.Records,
		ArchivedThrough: snapshot.ArchivedThrough, ArchiveCheckpoint: snapshot.ArchiveCheckpoint}
}

func activeLedgerMigrationOperationID(scope string, digest [sha256.Size]byte) (string, error) {
	material, err := json.Marshal(struct {
		Domain     string `json:"domain"`
		Scope      string `json:"scope"`
		Snapshot   string `json:"snapshot"`
	}{Domain: "wedecent-pairing-active-ledger-migration-v1", Scope: scope,
		Snapshot: hex.EncodeToString(digest[:])})
	if err != nil {
		return "", err
	}
	operation := sha256.Sum256(material)
	return hex.EncodeToString(operation[:]), nil
}

func verifyLegacyMigrationProofStateDigest(proof []byte, expected [sha256.Size]byte) error {
	var attestation struct {
		StateDigest string `json:"state_digest"`
	}
	if len(proof) == 0 || json.Unmarshal(proof, &attestation) != nil {
		return ErrRecoveryMigrationUntrusted
	}
	decoded, err := hex.DecodeString(attestation.StateDigest)
	if err != nil || len(decoded) != sha256.Size || !bytes.Equal(decoded, expected[:]) {
		return ErrRecoveryMigrationUntrusted
	}
	return nil
}

func pairingSnapshotDigest(snapshot pairingOutcomeSnapshotUnsigned) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func (r *PairingRecovery) verifyActiveLedgerSnapshot(ctx context.Context, snapshot pairingOutcomeSnapshot) error {
	if r == nil || r.authority == nil {
		return nil
	}
	scope := r.activeLedgerScope()
	head, err := r.authority.LoadCheckpoint(ctx, scope)
	if err != nil {
		return fmt.Errorf("%w: load active ledger checkpoint: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	if head.Scope != scope {
		return ErrRecoveryCheckpointConflict
	}
	if snapshot.AuthorityGeneration == 0 {
		if len(snapshot.Records) != 0 || snapshot.ArchivedThrough != 0 || snapshot.ArchiveCheckpoint != "" ||
			snapshot.AuthorityPreviousDigest != "" || snapshot.AuthorityStateDigest != "" ||
			!emptyRecoveryCheckpoint(snapshot.AuthorityCheckpoint) || !emptyRecoveryCheckpoint(head) {
			return ErrRecoveryMigrationUntrusted
		}
		return nil
	}
	checkpoint := snapshot.AuthorityCheckpoint
	digest, err := pairingSnapshotDigest(unsignedPairingSnapshot(snapshot))
	if err != nil {
		return err
	}
	previous, previousErr := hex.DecodeString(snapshot.AuthorityPreviousDigest)
	state, stateErr := hex.DecodeString(snapshot.AuthorityStateDigest)
	if previousErr != nil || stateErr != nil || len(previous) != sha256.Size || len(state) != sha256.Size ||
		checkpoint.Scope != scope || checkpoint.Generation != snapshot.AuthorityGeneration ||
		checkpoint.StateDigest != digest || hex.EncodeToString(digest[:]) != snapshot.AuthorityStateDigest ||
		!bytes.Equal(previous, checkpoint.PreviousDigest[:]) {
		return ErrRecoveryCheckpointConflict
	}
	if err := r.authority.VerifyCheckpoint(ctx, checkpoint); err != nil {
		return err
	}
	if err := ValidateRecoveryCheckpointWithTrust(RecoveryCheckpointRequest{
		Scope: scope, ExpectedGeneration: checkpoint.Generation - 1, Generation: checkpoint.Generation,
		PreviousDigest: checkpoint.PreviousDigest, StateDigest: checkpoint.StateDigest, OperationID: checkpoint.OperationID,
	}, checkpoint, r.authorityTrust); err != nil {
		return err
	}
	if !sameRecoveryCheckpoint(head, checkpoint) {
		return ErrRecoveryCheckpointStale
	}
	return nil
}

func (r *PairingRecovery) writeWithActiveLedgerAuthority(snapshot *pairingOutcomeSnapshot) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scope := r.activeLedgerScope()
	head, err := r.authority.LoadCheckpoint(ctx, scope)
	if err != nil {
		return fmt.Errorf("%w: load active ledger head: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	if head.Scope != scope {
		return ErrRecoveryCheckpointConflict
	}
	if snapshot.AuthorityGeneration == 0 {
		if !emptyRecoveryCheckpoint(head) {
			return ErrRecoveryCheckpointStale
		}
	} else {
		checkpoint := snapshot.AuthorityCheckpoint
		if checkpoint.Scope != scope || checkpoint.Generation != snapshot.AuthorityGeneration ||
			snapshot.AuthorityStateDigest != hex.EncodeToString(checkpoint.StateDigest[:]) ||
			snapshot.AuthorityPreviousDigest != hex.EncodeToString(checkpoint.PreviousDigest[:]) {
			return ErrRecoveryCheckpointConflict
		}
		if err := r.authority.VerifyCheckpoint(ctx, checkpoint); err != nil {
			return err
		}
		if !sameRecoveryCheckpoint(head, checkpoint) {
			return ErrRecoveryCheckpointStale
		}
		head = checkpoint
	}
	if head.Generation == ^uint64(0) {
		return ErrRecoveryCheckpointStale
	}
	unsigned := unsignedPairingSnapshot(*snapshot)
	digest, err := pairingSnapshotDigest(unsigned)
	if err != nil {
		return err
	}
	request, err := NewRecoveryCheckpointRequest(scope, head.Generation, head.StateDigest, digest)
	if err != nil {
		return err
	}
	pending := pairingOutcomeSnapshotPending{Unsigned: unsigned, Request: request}
	if err := r.writeActiveLedgerPending(pending); err != nil {
		return err
	}
	receipt, commitErr := r.authority.CommitCheckpoint(ctx, request)
	if commitErr != nil {
		observed, loadErr := r.authority.LoadCheckpoint(ctx, scope)
		if loadErr != nil || observed.Scope != request.Scope || observed.Generation != request.Generation ||
			observed.PreviousDigest != request.PreviousDigest || observed.StateDigest != request.StateDigest ||
			observed.OperationID != request.OperationID {
			return fmt.Errorf("%w: active ledger commit cannot be resolved: %v", ErrRecoveryCommitUncertain, commitErr)
		}
		receipt = observed
	}
	if err := validateRecoveryAuthorityReceipt(request, receipt, r.authorityTrust); err != nil {
		return err
	}
	snapshot.AuthorityGeneration = receipt.Generation
	snapshot.AuthorityPreviousDigest = hex.EncodeToString(receipt.PreviousDigest[:])
	snapshot.AuthorityStateDigest = hex.EncodeToString(receipt.StateDigest[:])
	snapshot.AuthorityCheckpoint = receipt
	if err := r.writeLocal(*snapshot); err != nil {
		return fmt.Errorf("%w: active ledger authority committed but local publication is uncertain: %v", ErrRecoveryCommitUncertain, err)
	}
	if err := r.removeActiveLedgerPending(); err != nil {
		return fmt.Errorf("%w: active ledger committed but pending marker cleanup failed: %v", ErrRecoveryCommitUncertain, err)
	}
	return nil
}

func (r *PairingRecovery) writeActiveLedgerPending(pending pairingOutcomeSnapshotPending) error {
	data, err := json.Marshal(pending)
	if err != nil || len(data) == 0 || len(data) > maxPairingOutcomeBytes*2 {
		return ErrRecoveryCheckpointConflict
	}
	pendingPath := r.path + ".authority-pending"
	if err := trust.VerifyPairingStatePath(filepath.Dir(r.path)); err != nil {
		return err
	}
	if _, err := os.Lstat(pendingPath); err == nil {
		return ErrRecoveryCommitUncertain
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.path), ".pairing-ledger-pending-*")
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
	if err := replaceAuditArchive(name, pendingPath); err != nil {
		return err
	}
	return syncAuditDirectory(filepath.Dir(r.path))
}

func (r *PairingRecovery) readActiveLedgerPending() (pairingOutcomeSnapshotPending, bool, error) {
	var pending pairingOutcomeSnapshotPending
	pendingPath := r.path + ".authority-pending"
	info, err := os.Lstat(pendingPath)
	if errors.Is(err, os.ErrNotExist) {
		return pending, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPairingOutcomeBytes*2 {
		return pending, false, ErrRecoveryCheckpointConflict
	}
	if err := trust.VerifyPairingStatePath(pendingPath); err != nil {
		return pending, false, err
	}
	file, err := os.Open(pendingPath)
	if err != nil {
		return pending, false, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return pending, false, ErrRecoveryCheckpointConflict
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxPairingOutcomeBytes*2+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > maxPairingOutcomeBytes*2 {
		return pending, false, ErrRecoveryCheckpointConflict
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pending); err != nil {
		return pending, false, ErrRecoveryCheckpointConflict
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return pending, false, ErrRecoveryCheckpointConflict
	}
	after, err := os.Lstat(pendingPath)
	if err != nil || !os.SameFile(opened, after) {
		return pending, false, ErrRecoveryCheckpointConflict
	}
	return pending, true, nil
}

func (r *PairingRecovery) removeActiveLedgerPending() error {
	pendingPath := r.path + ".authority-pending"
	if err := os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncAuditDirectory(filepath.Dir(r.path))
}

// reconcileActiveLedger resolves a prepared operation after restart. The
// prepared candidate is committed only against its exact prior generation and
// digest; an unrelated or advanced authority head fails closed.
func (r *PairingRecovery) reconcileActiveLedger() error {
	if r == nil || r.authority == nil {
		return ErrRecoveryAuthorityUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock, err := lockFile(r.path)
	if err != nil {
		return err
	}
	defer unlock()
	snapshot, err := r.read()
	if err != nil {
		return err
	}
	pending, found, err := r.readActiveLedgerPending()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if !found {
		return r.verifyActiveLedgerSnapshot(ctx, snapshot)
	}
	if pending.Request.Scope != r.activeLedgerScope() || pending.Request.Generation != pending.Request.ExpectedGeneration+1 {
		return ErrRecoveryCheckpointConflict
	}
	if pending.Migration != nil {
		migration := pending.Migration
		if migration.Scope != pending.Request.Scope || migration.ExpectedGeneration != pending.Request.ExpectedGeneration ||
			len(migration.AuthenticatedCheckpoint) == 0 || migration.MigrationOperationID == "" {
			return ErrRecoveryCheckpointConflict
		}
		raw, readErr := os.ReadFile(r.path)
		if readErr != nil || sha256.Sum256(raw) != migration.LegacyArchiveSHA256 {
			return ErrRecoveryMigrationUntrusted
		}
		expectedMigrationID, idErr := activeLedgerMigrationOperationID(migration.Scope, migration.LegacyArchiveSHA256)
		if idErr != nil || expectedMigrationID != migration.MigrationOperationID {
			return ErrRecoveryCheckpointConflict
		}
	}
	expectedRequest, requestErr := NewRecoveryCheckpointRequest(pending.Request.Scope, pending.Request.ExpectedGeneration,
		pending.Request.PreviousDigest, pending.Request.StateDigest)
	if requestErr != nil || expectedRequest.OperationID != pending.Request.OperationID {
		return ErrRecoveryCheckpointConflict
	}
	digest, err := pairingSnapshotDigest(pending.Unsigned)
	if err != nil || digest != pending.Request.StateDigest {
		return ErrRecoveryCheckpointConflict
	}
	candidate := pairingOutcomeSnapshot{Version: pending.Unsigned.Version, Records: pending.Unsigned.Records,
		ArchivedThrough: pending.Unsigned.ArchivedThrough, ArchiveCheckpoint: pending.Unsigned.ArchiveCheckpoint}
	if err := validatePairingSnapshot(candidate); err != nil {
		return ErrRecoveryCheckpointConflict
	}
	head, err := r.authority.LoadCheckpoint(ctx, r.activeLedgerScope())
	if err != nil {
		return fmt.Errorf("%w: resolve pending active ledger operation: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	if head.Scope != r.activeLedgerScope() {
		return ErrRecoveryCheckpointConflict
	}
	var receipt RecoveryCheckpoint
	if head.Generation == pending.Request.ExpectedGeneration && head.StateDigest == pending.Request.PreviousDigest {
		if pending.Migration != nil {
			receipt, err = r.authority.MigrateLegacyArchive(ctx, *pending.Migration)
		} else {
			receipt, err = r.authority.CommitCheckpoint(ctx, pending.Request)
		}
		if err != nil {
			observed, loadErr := r.authority.LoadCheckpoint(ctx, r.activeLedgerScope())
			if loadErr != nil || observed.Generation != pending.Request.Generation ||
				observed.StateDigest != pending.Request.StateDigest || observed.OperationID != pending.Request.OperationID ||
				observed.PreviousDigest != pending.Request.PreviousDigest {
				return fmt.Errorf("%w: pending active ledger commit remains uncertain: %v", ErrRecoveryCommitUncertain, err)
			}
			receipt = observed
		}
	} else if head.Generation == pending.Request.Generation && head.StateDigest == pending.Request.StateDigest &&
		head.OperationID == pending.Request.OperationID && head.PreviousDigest == pending.Request.PreviousDigest {
		receipt = head
	} else {
		return ErrRecoveryCheckpointStale
	}
	if err := validateRecoveryAuthorityReceipt(pending.Request, receipt, r.authorityTrust); err != nil {
		return err
	}
	candidate.AuthorityGeneration = receipt.Generation
	candidate.AuthorityPreviousDigest = hex.EncodeToString(receipt.PreviousDigest[:])
	candidate.AuthorityStateDigest = hex.EncodeToString(receipt.StateDigest[:])
	candidate.AuthorityCheckpoint = receipt
	if err := r.writeLocal(candidate); err != nil {
		return fmt.Errorf("%w: pending active ledger publication failed: %v", ErrRecoveryCommitUncertain, err)
	}
	return r.removeActiveLedgerPending()
}


// MigrateLegacyActiveLedger requires an out-of-band authority proof for the
// exact pre-migration snapshot. The provider must authenticate historical
// provenance and deduplicate MigrationOperationID across retries.
func (r *PairingRecovery) MigrateLegacyActiveLedger(ctx context.Context, authenticatedCheckpoint []byte) error {
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
	snapshot, err := r.read()
	if err != nil {
		return err
	}
	if snapshot.AuthorityGeneration != 0 {
		return r.verifyActiveLedgerSnapshot(ctx, snapshot)
	}
	if snapshot.AuthorityPreviousDigest != "" || snapshot.AuthorityStateDigest != "" ||
		!emptyRecoveryCheckpoint(snapshot.AuthorityCheckpoint) {
		return ErrRecoveryCheckpointConflict
	}
	pendingPath := r.path + ".authority-pending"
	if _, err := os.Lstat(pendingPath); err == nil {
		return ErrRecoveryCommitUncertain
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, err := os.Lstat(r.path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPairingOutcomeBytes {
		return ErrRecoveryMigrationUntrusted
	}
	if err := trust.VerifyPairingStatePath(r.path); err != nil {
		return err
	}
	file, err := os.Open(r.path)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return ErrRecoveryMigrationUntrusted
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxPairingOutcomeBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) > maxPairingOutcomeBytes {
		return ErrRecoveryMigrationUntrusted
	}
	if err := validatePairingSnapshot(snapshot); err != nil {
		return err
	}
	scope := r.activeLedgerScope()
	head, err := r.authority.LoadCheckpoint(ctx, scope)
	if err != nil {
		return fmt.Errorf("%w: load active ledger migration head: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	if head.Scope != scope || !emptyRecoveryCheckpoint(head) {
		return ErrRecoveryCheckpointStale
	}
	unsigned := unsignedPairingSnapshot(snapshot)
	stateDigest, err := pairingSnapshotDigest(unsigned)
	if err != nil {
		return err
	}
	archiveDigest := sha256.Sum256(raw)
	operationID, err := activeLedgerMigrationOperationID(scope, archiveDigest)
	if err != nil {
		return err
	}
	if err := verifyLegacyMigrationProofStateDigest(authenticatedCheckpoint, stateDigest); err != nil {
		return err
	}
	request, err := NewRecoveryCheckpointRequest(scope, head.Generation, head.StateDigest, stateDigest)
	if err != nil {
		return err
	}
	migration := LegacyRecoveryMigrationRequest{Scope: scope, LegacyArchiveSHA256: archiveDigest,
		ExpectedGeneration: head.Generation, AuthenticatedCheckpoint: append([]byte(nil), authenticatedCheckpoint...),
		MigrationOperationID: operationID}
	if err := r.writeActiveLedgerPending(pairingOutcomeSnapshotPending{
		Unsigned: unsigned, Request: request, Migration: &migration,
	}); err != nil {
		return err
	}
	checkpoint, commitErr := r.authority.MigrateLegacyArchive(ctx, migration)
	if commitErr != nil {
		observed, loadErr := r.authority.LoadCheckpoint(ctx, scope)
		if loadErr != nil || observed.Scope != scope || observed.Generation != request.Generation ||
			observed.PreviousDigest != request.PreviousDigest || observed.StateDigest != request.StateDigest ||
			observed.OperationID != request.OperationID {
			return fmt.Errorf("%w: active ledger migration outcome uncertain: %v", ErrRecoveryCommitUncertain, commitErr)
		}
		checkpoint = observed
	}
	if err := validateRecoveryAuthorityReceipt(request, checkpoint, r.authorityTrust); err != nil {
		return err
	}
	snapshot.AuthorityGeneration = checkpoint.Generation
	snapshot.AuthorityPreviousDigest = hex.EncodeToString(checkpoint.PreviousDigest[:])
	snapshot.AuthorityStateDigest = hex.EncodeToString(checkpoint.StateDigest[:])
	snapshot.AuthorityCheckpoint = checkpoint
	if err := r.writeLocal(snapshot); err != nil {
		return fmt.Errorf("%w: active ledger migration publication uncertain: %v", ErrRecoveryCommitUncertain, err)
	}
	if err := r.removeActiveLedgerPending(); err != nil {
		return fmt.Errorf("%w: active ledger migration pending cleanup uncertain: %v", ErrRecoveryCommitUncertain, err)
	}
	r.migrationPending = false
	return nil
}

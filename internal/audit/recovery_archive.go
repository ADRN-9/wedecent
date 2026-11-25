package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"crypto/ed25519"
	"time"
	"io"
	"os"
	"path/filepath"

	"wedecent.com/wedecent/internal/trust"
)

const (
	pairingArchiveFileName = "pairing-outcomes.archive.json"
	pairingArchiveKeyName  = "pairing-outcomes.archive.key"
	maxPairingArchiveBytes = 4 << 20
)

type pairingRecoveryArchiveUnsigned struct {
	Version       int              `json:"version"`
	FirstSequence uint64           `json:"first_sequence"`
	LastSequence  uint64           `json:"last_sequence"`
	Checkpoint    string           `json:"checkpoint"`
	Records       []PairingOutcome `json:"records"`
	AuthorityGeneration uint64 `json:"authority_generation,omitempty"``
	AuthorityPreviousDigest string `json:"authority_previous_digest,omitempty"``
}

type pairingRecoveryArchive struct {
	Version       int              `json:"version"`
	FirstSequence uint64           `json:"first_sequence"`
	LastSequence  uint64           `json:"last_sequence"`
	Checkpoint    string           `json:"checkpoint"`
	Records       []PairingOutcome `json:"records"`
	AuthorityGeneration uint64 `json:"authority_generation,omitempty"
	AuthorityPreviousDigest string `json:"authority_previous_digest,omitempty"
	AuthorityKeyID string `json:"authority_key_id,omitempty"`
	AuthoritySignature string `json:"authority_signature,omitempty"`
	AuthorityCheckpoint RecoveryCheckpoint `json:"authority_checkpoint,omitempty"`
	MAC           string           `json:"mac"`
}

func (r *PairingRecovery) loadArchiveKey() error {
	if r == nil {
		return errors.New("pairing recovery unavailable")
	}
	dir := filepath.Dir(r.path)
	path := filepath.Join(dir, pairingArchiveKeyName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, archiveErr := os.Lstat(filepath.Join(dir, pairingArchiveFileName)); archiveErr == nil {
			return errors.New("pairing recovery archive key missing: operator repair required")
		} else if !errors.Is(archiveErr, os.ErrNotExist) {
			return archiveErr
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return err
		}
		if _, err := f.Write(key); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := syncAuditDirectory(dir); err != nil {
			return fmt.Errorf("sync pairing archive key directory: %w", err)
		}
		if err := trust.VerifyPairingStatePath(path); err != nil {
			return err
		}
		r.archiveKey = key
		return nil
	}
	if err != nil {
		return err
	}
	if err := trust.VerifyPairingStatePath(path); err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != 32 {
		return errors.New("pairing recovery archive key has invalid type or size")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, after) {
		return errors.New("pairing recovery archive key changed during read")
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return errors.New("pairing recovery archive key is malformed")
	}
	r.archiveKey = key
	return nil
}

func (r *PairingRecovery) verifyArchiveKey() error {
	if r == nil || len(r.archiveKey) != 32 {
		return errors.New("pairing recovery archive authority unavailable")
	}
	path := filepath.Join(filepath.Dir(r.path), pairingArchiveKeyName)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := trust.VerifyPairingStatePath(path); err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != 32 {
		return errors.New("pairing recovery archive key has invalid type or size")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, after) {
		return errors.New("pairing recovery archive key changed during verification")
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 || !hmac.Equal(key, r.archiveKey) {
		return errors.New("pairing recovery archive key changed after initialization")
	}
	return nil
}

func pairingArchiveCheckpoint(records []PairingOutcome) (string, error) {
	checkpoint := make([]byte, sha256.Size)
	for i, record := range records {
		if record.Sequence != uint64(i+1) {
			return "", errors.New("pairing archive sequence discontinuity")
		}
		data, err := json.Marshal(record)
		if err != nil {
			return "", err
		}
		h := sha256.New()
		_, _ = h.Write(checkpoint)
		_, _ = h.Write(data)
		checkpoint = h.Sum(nil)
	}
	return hex.EncodeToString(checkpoint), nil
}


func ctxBackground() context.Context { return context.Background() }

func (r *PairingRecovery) authorizeArchivePublication(unsigned pairingRecoveryArchiveUnsigned, archive pairingRecoveryArchive) (pairingRecoveryArchiveUnsigned, pairingRecoveryArchive, error) {
	if r == nil || r.authority == nil {
		return unsigned, archive, ErrRecoveryAuthorityUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	head, err := r.authority.LoadCheckpoint(ctx, r.authorityScope)
	if err != nil {
		return unsigned, archive, fmt.Errorf("%w: load pairing archive checkpoint: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	if head.Generation > 0 {
		if err := r.verifyAuthorityCheckpoint(ctx, head); err != nil {
			return unsigned, archive, err
		}
	}
	build := func(generation uint64, previous [sha256.Size]byte) (pairingRecoveryArchiveUnsigned, []byte, [sha256.Size]byte, error) {
		candidate := unsigned
		candidate.AuthorityGeneration = generation
		candidate.AuthorityPreviousDigest = hex.EncodeToString(previous[:])
		payload, marshalErr := json.Marshal(candidate)
		if marshalErr != nil {
			return candidate, nil, [sha256.Size]byte{}, marshalErr
		}
		return candidate, payload, sha256.Sum256(payload), nil
	}
	var candidate pairingRecoveryArchiveUnsigned
	var payload []byte
	var digest [sha256.Size]byte
	if head.Generation > 0 {
		candidate, payload, digest, err = build(head.Generation, head.PreviousDigest)
		if err != nil {
			return unsigned, archive, err
		}
	}
	if head.Generation == 0 || digest != head.StateDigest {
		if head.Generation == ^uint64(0) {
			return unsigned, archive, ErrRecoveryCheckpointStale
		}
		candidate, payload, digest, err = build(head.Generation+1, head.StateDigest)
		if err != nil {
			return unsigned, archive, err
		}
	}
	keyID, signature, err := r.authority.SignArchive(ctx, payload)
	if err != nil {
		return unsigned, archive, fmt.Errorf("%w: sign pairing archive: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	if keyID == "" || len(keyID) > 128 || len(signature) != ed25519.SignatureSize {
		return unsigned, archive, ErrRecoveryCheckpointConflict
	}
	var receipt RecoveryCheckpoint
	if head.Generation > 0 && digest == head.StateDigest {
		receipt = head
	} else {
		request, requestErr := NewRecoveryCheckpointRequest(r.authorityScope, candidate.AuthorityGeneration-1, head.StateDigest, digest)
		if requestErr != nil {
			return unsigned, archive, requestErr
		}
		receipt, err = r.authority.CommitCheckpoint(ctx, request)
		if err != nil {
			observed, loadErr := r.authority.LoadCheckpoint(ctx, r.authorityScope)
			if loadErr != nil || observed.Scope != request.Scope || observed.Generation != request.Generation ||
				observed.StateDigest != request.StateDigest || observed.PreviousDigest != request.PreviousDigest ||
				observed.OperationID != request.OperationID {
				return unsigned, archive, fmt.Errorf("%w: %v", ErrRecoveryCommitUncertain, err)
			}
			receipt = observed
		}
	}
	request, err := NewRecoveryCheckpointRequest(r.authorityScope, receipt.Generation-1, receipt.PreviousDigest, receipt.StateDigest)
	if err != nil {
		return unsigned, archive, err
	}
	if receipt.StateDigest != digest || receipt.Generation != candidate.AuthorityGeneration ||
		receipt.PreviousDigest != head.StateDigest || receipt.OperationID != request.OperationID {
		return unsigned, archive, ErrRecoveryCheckpointConflict
	}
	if err := r.authority.VerifyCheckpoint(ctx, receipt); err != nil {
		return unsigned, archive, fmt.Errorf("%w: provider checkpoint verification: %v", ErrRecoveryCheckpointConflict, err)
	}
	if err := ValidateRecoveryCheckpointWithTrust(request, receipt, r.authorityTrust); err != nil {
		return unsigned, archive, err
	}
	if err := r.authority.VerifyArchive(ctx, keyID, payload, signature); err != nil {
		return unsigned, archive, fmt.Errorf("%w: archive signature verification: %v", ErrRecoveryCheckpointConflict, err)
	}
	archive.AuthorityGeneration = candidate.AuthorityGeneration
	archive.AuthorityPreviousDigest = candidate.AuthorityPreviousDigest
	archive.AuthorityKeyID = keyID
	archive.AuthoritySignature = hex.EncodeToString(signature)
	archive.AuthorityCheckpoint = receipt
	return candidate, archive, nil
}

func (r *PairingRecovery) verifyIndependentArchive(ctx context.Context, archive pairingRecoveryArchive, payload []byte) error {
	if r == nil || r.authority == nil {
		return ErrRecoveryAuthorityUnavailable
	}
	if archive.AuthorityGeneration == 0 || archive.AuthorityKeyID == "" || archive.AuthorityPreviousDigest == "" ||
		archive.AuthoritySignature == "" || archive.AuthorityCheckpoint.Generation == 0 {
		return ErrRecoveryMigrationUntrusted
	}
	previousBytes, err := hex.DecodeString(archive.AuthorityPreviousDigest)
	if err != nil || len(previousBytes) != sha256.Size {
		return ErrRecoveryMigrationUntrusted
	}
	var previous [sha256.Size]byte
	copy(previous[:], previousBytes)
	if archive.AuthorityCheckpoint.Generation != archive.AuthorityGeneration ||
		archive.AuthorityCheckpoint.PreviousDigest != previous ||
		archive.AuthorityCheckpoint.StateDigest != sha256.Sum256(payload) {
		return ErrRecoveryCheckpointConflict
	}
	signature, err := hex.DecodeString(archive.AuthoritySignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrRecoveryCheckpointConflict
	}
	if err := r.authority.VerifyArchive(ctx, archive.AuthorityKeyID, payload, signature); err != nil {
		return fmt.Errorf("%w: independent archive signature rejected: %v", ErrRecoveryCheckpointConflict, err)
	}
	checkpoint := archive.AuthorityCheckpoint
	request, err := NewRecoveryCheckpointRequest(r.authorityScope, checkpoint.Generation-1, checkpoint.PreviousDigest, checkpoint.StateDigest)
	if err != nil {
		return err
	}
	if err := r.authority.VerifyCheckpoint(ctx, checkpoint); err != nil {
		return fmt.Errorf("%w: independent checkpoint rejected: %v", ErrRecoveryCheckpointConflict, err)
	}
	if err := ValidateRecoveryCheckpointWithTrust(request, checkpoint, r.authorityTrust); err != nil {
		return err
	}
	head, err := r.authority.LoadCheckpoint(ctx, r.authorityScope)
	if err != nil {
		return fmt.Errorf("%w: current independent checkpoint unavailable: %v", ErrRecoveryAuthorityUnavailable, err)
	}
	if !sameRecoveryCheckpoint(head, checkpoint) {
		return ErrRecoveryCheckpointStale
	}
	return nil
}

func (r *PairingRecovery) verifyAuthorityCheckpoint(ctx context.Context, checkpoint RecoveryCheckpoint) error {
	if checkpoint.Generation == 0 {
		return ErrRecoveryCheckpointStale
	}
	request, err := NewRecoveryCheckpointRequest(r.authorityScope, checkpoint.Generation-1, checkpoint.PreviousDigest, checkpoint.StateDigest)
	if err != nil {
		return err
	}
	if err := r.authority.VerifyCheckpoint(ctx, checkpoint); err != nil {
		return fmt.Errorf("%w: independent checkpoint verification failed: %v", ErrRecoveryCheckpointConflict, err)
	}
	return ValidateRecoveryCheckpointWithTrust(request, checkpoint, r.authorityTrust)
}

func sameRecoveryCheckpoint(a, b RecoveryCheckpoint) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	return errLeft == nil && errRight == nil && bytes.Equal(left, right)
}

func (r *PairingRecovery) readArchive() (pairingRecoveryArchive, error) {
	archive := pairingRecoveryArchive{Version: 1}
	if err := r.verifyArchiveKey(); err != nil {
		return archive, err
	}
	path := filepath.Join(filepath.Dir(r.path), pairingArchiveFileName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return archive, nil
	}
	if err != nil {
		return archive, err
	}
	if err := trust.VerifyPairingStatePath(path); err != nil {
		return archive, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPairingArchiveBytes {
		return archive, errors.New("pairing recovery archive type or size invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		return archive, err
	}
	defer f.Close()
	opened, err := f.Stat()
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, after) {
		return archive, errors.New("pairing recovery archive changed during read")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPairingArchiveBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxPairingArchiveBytes {
		return archive, errors.New("pairing recovery archive read failed or exceeded limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&archive); err != nil {
		return archive, fmt.Errorf("parse pairing recovery archive: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return archive, errors.New("pairing recovery archive trailing data")
	}
	if archive.Version != 1 || archive.FirstSequence != 1 || archive.LastSequence == 0 ||
		uint64(len(archive.Records)) != archive.LastSequence || len(archive.Records) == 0 {
		return archive, errors.New("pairing recovery archive header invalid")
	}
	for _, record := range archive.Records {
		if err := validatePairingOutcome(record); err != nil {
			return archive, err
		}
		if record.Outcome != PairingOutcomeSuccess && record.Outcome != PairingOutcomeDenied {
			return archive, errors.New("pairing recovery archive contains unresolved outcome")
		}
		if record.AuditProof == nil || record.AcknowledgedAt == nil {
			return archive, errors.New("pairing recovery archive contains unverified outcome")
		}
	}
	checkpoint, err := pairingArchiveCheckpoint(archive.Records)
	if err != nil || checkpoint != archive.Checkpoint {
		return archive, errors.New("pairing recovery archive checkpoint mismatch")
	}
	unsigned := pairingRecoveryArchiveUnsigned{Version: archive.Version, FirstSequence: archive.FirstSequence,
		LastSequence: archive.LastSequence, Checkpoint: archive.Checkpoint, Records: archive.Records,
		AuthorityGeneration: archive.AuthorityGeneration, AuthorityPreviousDigest: archive.AuthorityPreviousDigest}
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return archive, err
	}
	mac := hmac.New(sha256.New, r.archiveKey)
	_, _ = mac.Write(payload)
	provided, decodeErr := hex.DecodeString(archive.MAC)
	if decodeErr != nil || !hmac.Equal(provided, mac.Sum(nil)) {
		return archive, errors.New("pairing recovery archive authentication failed")
	}
	if r.authority != nil {
		if err := r.verifyIndependentArchive(ctxBackground(), archive, payload); err != nil {
			return archive, err
		}
	}
	return archive, nil
}

func (r *PairingRecovery) writeArchive(records []PairingOutcome) (pairingRecoveryArchive, error) {
	var empty pairingRecoveryArchive
	if len(records) == 0 {
		return empty, errors.New("pairing recovery archive input invalid")
	}
	if err := r.verifyArchiveKey(); err != nil {
		return empty, err
	}
	checkpoint, err := pairingArchiveCheckpoint(records)
	if err != nil {
		return empty, err
	}
	unsigned := pairingRecoveryArchiveUnsigned{Version: 1, FirstSequence: 1, LastSequence: uint64(len(records)), Checkpoint: checkpoint, Records: records}
	archive := pairingRecoveryArchive{Version: 1, FirstSequence: 1, LastSequence: uint64(len(records)), Checkpoint: checkpoint, Records: records}
	if r.authority != nil {
		var err error
		unsigned, archive, err = r.authorizeArchivePublication(unsigned, archive)
		if err != nil {
			return empty, err
		}
	}
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return empty, err
	}
	mac := hmac.New(sha256.New, r.archiveKey)
	_, _ = mac.Write(payload)
	archive.MAC = hex.EncodeToString(mac.Sum(nil))
	data, err := json.Marshal(archive)
	if err != nil {
		return empty, err
	}
	if len(data) == 0 || len(data) > maxPairingArchiveBytes {
		return empty, errors.New("pairing recovery archive capacity reached")
	}
	dir := filepath.Dir(r.path)
	tmp, err := os.CreateTemp(dir, ".pairing-outcomes-archive-*")
	if err != nil {
		return empty, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return empty, err
	}
	if err := trust.VerifyPairingStatePath(name); err != nil {
		_ = tmp.Close()
		return empty, err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return empty, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return empty, err
	}
	if err := tmp.Close(); err != nil {
		return empty, err
	}
	if err := replaceAuditArchive(name, filepath.Join(dir, pairingArchiveFileName)); err != nil {
		return empty, fmt.Errorf("pairing recovery archive replacement uncertain: %w", err)
	}
	if err := syncAuditDirectory(dir); err != nil {
		return empty, fmt.Errorf("pairing recovery archive directory sync uncertain: %w", err)
	}
	if r.archiveAfterSync != nil {
		if err := r.archiveAfterSync(); err != nil {
			return empty, err
		}
	}
	return r.readArchive()
}

func (r *PairingRecovery) reconcileArchive(snapshot *pairingOutcomeSnapshot, archive pairingRecoveryArchive) (bool, error) {
	if snapshot.ArchivedThrough > archive.LastSequence {
		return false, errors.New("pairing recovery checkpoint is ahead of authenticated archive")
	}
	if snapshot.ArchivedThrough == archive.LastSequence {
		if archive.LastSequence > 0 && snapshot.ArchiveCheckpoint != archive.Checkpoint {
			return false, errors.New("active ledger checkpoint does not match authenticated archive")
		}
		if archive.LastSequence == 0 && snapshot.ArchiveCheckpoint != "" {
			return false, errors.New("active ledger references a missing archive checkpoint")
		}
		return false, nil
	}
	if archive.LastSequence == 0 {
		if snapshot.ArchivedThrough != 0 {
			return false, errors.New("pairing recovery archive disappeared after compaction")
		}
		return false, nil
	}
	count := archive.LastSequence - snapshot.ArchivedThrough
	if count > uint64(len(snapshot.Records)) {
		return false, errors.New("pairing archive advanced beyond active recovery records")
	}
	for i := uint64(0); i < count; i++ {
		active, archived := snapshot.Records[i], archive.Records[snapshot.ArchivedThrough+i]
		left, _ := json.Marshal(active)
		right, _ := json.Marshal(archived)
		if !bytes.Equal(left, right) {
			return false, errors.New("pairing archive and active ledger disagree at compaction boundary")
		}
	}
	snapshot.Records = append([]PairingOutcome(nil), snapshot.Records[count:]...)
	snapshot.ArchivedThrough = archive.LastSequence
	snapshot.ArchiveCheckpoint = archive.Checkpoint
	return true, nil
}

func (r *PairingRecovery) assignSequences(snapshot *pairingOutcomeSnapshot, archiveLast uint64) (bool, error) {
	if snapshot.ArchivedThrough != archiveLast {
		return false, errors.New("pairing recovery active/archive checkpoint mismatch")
	}
	expected := archiveLast + 1
	changed := snapshot.Version != pairingOutcomeVersion
	snapshot.Version = pairingOutcomeVersion
	for i := range snapshot.Records {
		record := &snapshot.Records[i]
		if record.Sequence == 0 {
			record.Sequence = expected
			changed = true
		}
		if record.Sequence != expected {
			return changed, errors.New("pairing recovery record sequence discontinuity")
		}
		expected++
	}
	return changed, nil
}

// CompactResolved archives only a contiguous prefix of resolved records whose
// completion proof was independently verified and explicitly acknowledged.
// The authenticated archive is synced before active-ledger compaction.
func (r *PairingRecovery) CompactResolved() error {
	if r == nil {
		return errors.New("pairing recovery unavailable")
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
	if err := trust.VerifyPairingStatePath(r.path + ".lock"); err != nil {
		return err
	}
	snapshot, err := r.read()
	if err != nil {
		return err
	}
	archive, err := r.readArchive()
	if err != nil {
		return err
	}
	changed, err := r.reconcileArchive(&snapshot, archive)
	if err != nil {
		return err
	}
	assigned, err := r.assignSequences(&snapshot, archive.LastSequence)
	if err != nil {
		return err
	}
	if changed || assigned {
		if err := r.write(snapshot); err != nil {
			return err
		}
	}
	count := 0
	for _, record := range snapshot.Records {
		if record.Sequence != archive.LastSequence+uint64(count)+1 ||
			(record.Outcome != PairingOutcomeSuccess && record.Outcome != PairingOutcomeDenied) ||
			record.AuditProof == nil || record.AcknowledgedAt == nil {
			break
		}
		count++
	}
	if count == 0 {
		return nil
	}
	records := make([]PairingOutcome, 0, len(archive.Records)+count)
	records = append(records, archive.Records...)
	records = append(records, snapshot.Records[:count]...)
	verified, err := r.writeArchive(records)
	if err != nil {
		return err
	}
	if verified.LastSequence != uint64(len(records)) {
		return errors.New("pairing recovery archive verification returned wrong checkpoint")
	}
	snapshot.Records = append([]PairingOutcome(nil), snapshot.Records[count:]...)
	snapshot.ArchivedThrough = verified.LastSequence
	snapshot.ArchiveCheckpoint = verified.Checkpoint
	if r.compactionBeforeReplace != nil {
		if err := r.compactionBeforeReplace(); err != nil {
			return fmt.Errorf("pairing archive durable but active compaction interrupted: %w", err)
		}
	}
	if err := r.write(snapshot); err != nil {
		return fmt.Errorf("pairing archive durable but active compaction uncertain: %w", err)
	}
	return nil
}

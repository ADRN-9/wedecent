package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
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
}

type pairingRecoveryArchive struct {
	Version       int              `json:"version"`
	FirstSequence uint64           `json:"first_sequence"`
	LastSequence  uint64           `json:"last_sequence"`
	Checkpoint    string           `json:"checkpoint"`
	Records       []PairingOutcome `json:"records"`
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
		LastSequence: archive.LastSequence, Checkpoint: archive.Checkpoint, Records: archive.Records}
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
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return empty, err
	}
	mac := hmac.New(sha256.New, r.archiveKey)
	_, _ = mac.Write(payload)
	archive := pairingRecoveryArchive{Version: 1, FirstSequence: 1, LastSequence: uint64(len(records)),
		Checkpoint: checkpoint, Records: records, MAC: hex.EncodeToString(mac.Sum(nil))}
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

package audit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"wedecent.com/wedecent/internal/trust"
)

const (
	PairingOutcomeFileName  = "pairing-outcomes.json"
	maxPairingOutcomes      = 64
	maxPairingOutcomeBytes  = 64 << 10
	PairingOutcomePending   = "pending"
	PairingOutcomeSuccess   = "success"
	PairingOutcomeDenied    = "denied"
	PairingOutcomeFailed    = "failed"
	PairingOutcomeUncertain = "uncertain"
)

var pairingIdentityPattern = regexp.MustCompile(`^wd_[a-z2-7]{16}$`)
var pairingFingerprintPattern = regexp.MustCompile(`^SHA256:[0-9A-Fa-f]{64}$`)
var pairingAttemptPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type PairingOutcome struct {
	AttemptID      string             `json:"attempt_id"`
	ActorID        string             `json:"actor_id"`
	PeerID         string             `json:"peer_id"`
	Fingerprint    string             `json:"fingerprint"`
	CredentialGeneration uint64 `json:"credential_generation,omitempty"`
	Sequence uint64 `json:"sequence,omitempty"`
	Outcome        string             `json:"outcome"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
	AuditProof     *PairingAuditProof `json:"audit_proof,omitempty"`
	AcknowledgedAt *time.Time         `json:"acknowledged_at,omitempty"`
}

// PairingAuditProof is a durable, nonrotating copy of an independently
// verified completion or privileged reconciliation audit event. It is not a
// caller-supplied assertion that a rotating log append succeeded.
type PairingAuditProof struct {
	Kind       string    `json:"kind"`
	Event      Event     `json:"event"`
	VerifiedAt time.Time `json:"verified_at"`
}

type pairingOutcomeSnapshot struct {
	Version int `json:"version"`
	Records []PairingOutcome `json:"records"`
	ArchivedThrough uint64 `json:"archived_through,omitempty"`
}

// PairingRecovery is independent of rotating audit files. Entries never
// expire or disappear automatically, including when capacity is reached.
type PairingRecovery struct {
	path          string
	syncDirectory func(string) error
	beforeReplace func() error
	afterReplace  func() error
	beforeRead    func() error
	allowEmpty    bool
	operatorCheck func() error // test-only authorization fault seam
	archiveKey []byte
	archiveAfterSync func() error
}

func NewPairingAttemptID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func OpenPairingRecovery(stateDir string) (*PairingRecovery, error) {
	if stateDir == "" {
		return nil, errors.New("pairing recovery state directory is required")
	}
	dir := filepath.Clean(stateDir)
	if err := trust.VerifyPairingStatePath(dir); err != nil {
		return nil, fmt.Errorf("unsafe pairing recovery directory: %w", err)
	}
	if err := syncAuditDirectory(dir); err != nil {
		return nil, fmt.Errorf("pairing recovery durability unavailable: %w", err)
	}
	r := &PairingRecovery{path: filepath.Join(dir, PairingOutcomeFileName)}
	// Initialization is serialized with mutation. A second opener must not
	// confuse an in-progress first creation with a deleted durable ledger.
	unlock, err := lockFile(r.path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := r.loadArchiveKey(); err != nil { return nil, err }
	if err := trust.VerifyPairingStatePath(r.path + ".lock"); err != nil {
		return nil, err
	}
	initialized, err := r.initialized()
	if err != nil {
		return nil, err
	}
	_, stateErr := os.Lstat(r.path)
	if errors.Is(stateErr, os.ErrNotExist) {
		if initialized {
			return nil, errors.New("pairing recovery file missing after initialization: operator repair required")
		}
		r.allowEmpty = true
		if err := r.write(pairingOutcomeSnapshot{Version: 1}); err != nil {
			return nil, err
		}
		r.allowEmpty = false
	} else if stateErr != nil {
		return nil, stateErr
	}
	snapshot, err := r.read()
	if err != nil { return nil, err }
	archive, err := r.readArchive()
	if err != nil { return nil, err }
	changed, err := r.reconcileArchive(&snapshot, archive)
	if err != nil { return nil, err }
	assigned, err := r.assignSequences(&snapshot, archive.LastSequence)
	if err != nil { return nil, err }
	if changed || assigned {
		if err := r.write(snapshot); err != nil { return nil, fmt.Errorf("pairing recovery archive reconciliation: %w", err) }
	}
	if !initialized {
		if err := r.markInitialized(); err != nil {
			return nil, fmt.Errorf("sync pairing recovery initialization: %w", err)
		}
	}
	return r, nil
}

// The marker lives beyond byte zero because Windows LockFileEx locks byte
// zero. A synced marker distinguishes deleted state from concurrent creation.
const pairingRecoveryInitMarker = "WD-C16"

func (r *PairingRecovery) initialized() (bool, error) {
	f, err := os.OpenFile(r.path+".lock", os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, len(pairingRecoveryInitMarker))
	n, err := f.ReadAt(buf, 1)
	if n == 0 && errors.Is(err, io.EOF) {
		return false, nil
	}
	if err != nil || n != len(buf) || string(buf) != pairingRecoveryInitMarker {
		return false, errors.New("invalid pairing recovery lock initialization marker")
	}
	return true, nil
}

func (r *PairingRecovery) markInitialized() error {
	f, err := os.OpenFile(r.path+".lock", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte(pairingRecoveryInitMarker), 1); err != nil {
		return err
	}
	return f.Sync()
}

func validPairingOutcomeState(state string) bool {
	switch state {
	case PairingOutcomePending, PairingOutcomeSuccess, PairingOutcomeDenied, PairingOutcomeFailed, PairingOutcomeUncertain:
		return true
	}
	return false
}

func validatePairingProof(record PairingOutcome, proof PairingAuditProof) error {
	event := proof.Event
	if proof.VerifiedAt.IsZero() || event.Time.IsZero() ||
		proof.VerifiedAt.Before(event.Time) ||
		event.AttemptID != record.AttemptID ||
		event.ActorID != record.ActorID || event.PeerID != record.PeerID {
		return errors.New("pairing recovery audit proof identity or timestamp mismatch")
	}
	copyEvent := event
	if err := validateEvent(&copyEvent); err != nil || copyEvent != event {
		return errors.New("pairing recovery audit proof event is invalid")
	}
	switch proof.Kind {
	case "completion":
		if (record.Outcome == PairingOutcomeSuccess &&
			event.Type == "pairing.trust_added" && event.Outcome == "success") ||
			(record.Outcome == PairingOutcomeDenied &&
				event.Type == "pairing.request" && event.Outcome == "denied") {
			return nil
		}
	case "reconciliation":
		if record.Outcome == PairingOutcomeSuccess &&
			event.Type == "pairing.reconciliation" && event.Outcome == "success" &&
			event.Reason == "privileged_trust_review" {
			return nil
		}
	}
	return errors.New("pairing recovery audit proof type or outcome mismatch")
}

func validatePairingOutcome(record PairingOutcome) error {
	if !pairingAttemptPattern.MatchString(record.AttemptID) ||
		!pairingIdentityPattern.MatchString(record.ActorID) ||
		!pairingIdentityPattern.MatchString(record.PeerID) ||
		!pairingFingerprintPattern.MatchString(record.Fingerprint) ||
		!validPairingOutcomeState(record.Outcome) ||
		record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() ||
		record.UpdatedAt.Before(record.CreatedAt) {
		return errors.New("invalid pairing recovery record")
	}
	if record.AuditProof != nil {
		if err := validatePairingProof(record, *record.AuditProof); err != nil {
			return err
		}
	}
	if record.AcknowledgedAt != nil {
		if record.AuditProof == nil || record.AcknowledgedAt.IsZero() ||
			record.AcknowledgedAt.Before(record.AuditProof.VerifiedAt) {
			return errors.New("pairing acknowledged without verified durable audit proof")
		}
	}
	return nil
}

func validatePairingSnapshot(s pairingOutcomeSnapshot) error {
	if s.Version != 1 || len(s.Records) > maxPairingOutcomes {
		return errors.New("invalid pairing recovery version or capacity")
	}
	seen := make(map[string]bool, len(s.Records))
	for _, record := range s.Records {
		if err := validatePairingOutcome(record); err != nil {
			return err
		}
		if seen[record.AttemptID] {
			return errors.New("duplicate pairing recovery attempt")
		}
		seen[record.AttemptID] = true
	}
	return nil
}

func (r *PairingRecovery) read() (pairingOutcomeSnapshot, error) {
	empty := pairingOutcomeSnapshot{Version: 1}
	if r == nil {
		return empty, errors.New("pairing recovery unavailable")
	}
	if r.beforeRead != nil {
		if err := r.beforeRead(); err != nil {
			return empty, err
		}
	}
	info, err := os.Lstat(r.path)
	if errors.Is(err, os.ErrNotExist) {
		if !r.allowEmpty {
			return empty, errors.New("pairing recovery file disappeared")
		}
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	if err := trust.VerifyPairingStatePath(r.path); err != nil {
		return empty, fmt.Errorf("unsafe pairing recovery file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPairingOutcomeBytes {
		return empty, errors.New("pairing recovery invalid type or size")
	}
	f, err := os.Open(r.path)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return empty, errors.New("pairing recovery changed during read")
	}
	onPath, err := os.Lstat(r.path)
	if err != nil || !os.SameFile(opened, onPath) {
		return empty, errors.New("pairing recovery path was replaced")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPairingOutcomeBytes+1))
	if err != nil {
		return empty, err
	}
	if len(data) == 0 || len(data) > maxPairingOutcomeBytes {
		return empty, errors.New("pairing recovery size exceeded")
	}
	var snapshot pairingOutcomeSnapshot
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return empty, fmt.Errorf("parse pairing recovery: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return empty, errors.New("pairing recovery trailing data")
	}
	if err := validatePairingSnapshot(snapshot); err != nil {
		return empty, err
	}
	return snapshot, nil
}

func (r *PairingRecovery) withLock(change func(*pairingOutcomeSnapshot) error) error {
	if err := trust.VerifyPairingStatePath(filepath.Dir(r.path)); err != nil {
		return fmt.Errorf("unsafe pairing recovery root: %w", err)
	}
	unlock, err := lockFile(r.path)
	if err != nil {
		return err
	}
	defer unlock()
	if err := trust.VerifyPairingStatePath(r.path + ".lock"); err != nil {
		return fmt.Errorf("unsafe pairing recovery lock: %w", err)
	}
	snapshot, err := r.read()
	if err != nil { return err }
	archive, err := r.readArchive()
	if err != nil { return err }
	changed, err := r.reconcileArchive(&snapshot, archive)
	if err != nil { return err }
	assigned, err := r.assignSequences(&snapshot, archive.LastSequence)
	if err != nil { return err }
	if changed || assigned {
		if err := r.write(snapshot); err != nil { return fmt.Errorf("pairing archive recovery reconciliation: %w", err) }
	}
	if err := change(&snapshot); err != nil { return err }
	if _, err := r.assignSequences(&snapshot, archive.LastSequence); err != nil { return err }
	if err := validatePairingSnapshot(snapshot); err != nil { return err }
	if err := r.write(snapshot); err != nil {
		if _, statErr := os.Lstat(r.path); statErr == nil {
			r.allowEmpty = false
		}
		return err
	}
	r.allowEmpty = false
	return nil
}

func (r *PairingRecovery) write(snapshot pairingOutcomeSnapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxPairingOutcomeBytes {
		return errors.New("pairing recovery size limit exceeded")
	}
	dir := filepath.Dir(r.path)
	tmp, err := os.CreateTemp(dir, ".pairing-outcomes-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	closeWith := func(err error) error {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return closeWith(err)
	}
	if err := trust.VerifyPairingStatePath(name); err != nil {
		return closeWith(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return closeWith(err)
	}
	if err := tmp.Sync(); err != nil {
		return closeWith(err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if r.beforeReplace != nil {
		if err := r.beforeReplace(); err != nil {
			return err
		}
	}
	if err := replaceAuditArchive(name, r.path); err != nil {
		return fmt.Errorf("pairing recovery replacement uncertain: %w", err)
	}
	if err := trust.VerifyPairingStatePath(r.path); err != nil {
		return fmt.Errorf("pairing recovery protection uncertain: %w", err)
	}
	if r.afterReplace != nil {
		if err := r.afterReplace(); err != nil {
			return fmt.Errorf("pairing recovery durability uncertain: %w", err)
		}
	}
	syncDirectory := syncAuditDirectory
	if r.syncDirectory != nil {
		syncDirectory = r.syncDirectory
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("pairing recovery directory sync uncertain: %w", err)
	}
	return nil
}

// Begin must be synchronized before consuming the secret. Full or unsafe
// recovery state blocks new pairings instead of evicting unresolved evidence.
func (r *PairingRecovery) Begin(record PairingOutcome) error {
	record.Outcome = PairingOutcomePending
	now := time.Now().UTC()
	record.CreatedAt, record.UpdatedAt = now, now
	if err := validatePairingOutcome(record); err != nil {
		return err
	}
	return r.withLock(func(snapshot *pairingOutcomeSnapshot) error {
		if len(snapshot.Records) >= maxPairingOutcomes {
			return errors.New("pairing recovery capacity reached: operator review required")
		}
		for _, entry := range snapshot.Records {
			if entry.AttemptID == record.AttemptID {
				return errors.New("pairing recovery duplicate attempt")
			}
		}
		snapshot.Records = append(snapshot.Records, record)
		return nil
	})
}

// Reserve binds one durable admission attempt to a credential generation and
// the authenticated peer identity. A matching pending reservation is returned
// for interrupted-operation recovery; a different identity or resolved attempt
// cannot reuse the same generation.
func (r *PairingRecovery) Reserve(record PairingOutcome) (PairingOutcome, error) {
	if record.CredentialGeneration == 0 { return PairingOutcome{}, errors.New("pairing credential generation is required") }
	record.Outcome = PairingOutcomePending
	now := time.Now().UTC()
	record.CreatedAt, record.UpdatedAt = now, now
	if err := validatePairingOutcome(record); err != nil { return PairingOutcome{}, err }
	var reserved PairingOutcome
	err := r.withLock(func(snapshot *pairingOutcomeSnapshot) error {
		for _, existing := range snapshot.Records {
			if existing.CredentialGeneration != record.CredentialGeneration { continue }
			if existing.ActorID != record.ActorID || existing.PeerID != record.PeerID || existing.Fingerprint != record.Fingerprint {
				return errors.New("pairing credential generation is reserved for a different device identity")
			}
			if existing.Outcome != PairingOutcomePending {
				return errors.New("pairing credential generation already has a resolved attempt")
			}
			reserved = existing
			return nil
		}
		if len(snapshot.Records) >= maxPairingOutcomes { return errors.New("pairing recovery capacity reached: operator review required") }
		snapshot.Records = append(snapshot.Records, record)
		reserved = record
		return nil
	})
	return reserved, err
}

func (r *PairingRecovery) Complete(attemptID, outcome string) error {
	if !pairingAttemptPattern.MatchString(attemptID) || !validPairingOutcomeState(outcome) || outcome == PairingOutcomePending {
		return errors.New("invalid pairing recovery completion")
	}
	return r.withLock(func(snapshot *pairingOutcomeSnapshot) error {
		for i := range snapshot.Records {
			if snapshot.Records[i].AttemptID == attemptID {
				if snapshot.Records[i].Outcome != PairingOutcomePending && snapshot.Records[i].Outcome != outcome {
					return errors.New("pairing outcome transition not permitted")
				}
				snapshot.Records[i].Outcome = outcome
				snapshot.Records[i].UpdatedAt = time.Now().UTC()
				return nil
			}
		}
		return errors.New("pairing recovery attempt not found")
	})
}

func (r *PairingRecovery) Records() ([]PairingOutcome, error) {
	if r == nil {
		return nil, errors.New("pairing recovery unavailable")
	}
	if err := trust.VerifyPairingStatePath(filepath.Dir(r.path)); err != nil {
		return nil, err
	}
	unlock, err := lockFile(r.path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := trust.VerifyPairingStatePath(r.path + ".lock"); err != nil {
		return nil, err
	}
	snapshot, err := r.read()
	if err != nil { return nil, err }
	archive, err := r.readArchive()
	if err != nil { return nil, err }
	changed, err := r.reconcileArchive(&snapshot, archive)
	if err != nil { return nil, err }
	assigned, err := r.assignSequences(&snapshot, archive.LastSequence)
	if err != nil { return nil, err }
	if changed || assigned {
		if err := r.write(snapshot); err != nil { return nil, fmt.Errorf("pairing archive reconciliation: %w", err) }
	}
	all := make([]PairingOutcome, 0, len(archive.Records)+len(snapshot.Records))
	all = append(all, archive.Records...)
	all = append(all, snapshot.Records...)
	return all, nil
}

// AcknowledgeResolved never deletes evidence. It records review of an
// independently verified completion in the same bounded durable register.
// Full registers require an approved offline evidence export/repair procedure.
func (r *PairingRecovery) AcknowledgeResolved(attemptID string) error {
	if !pairingAttemptPattern.MatchString(attemptID) {
		return errors.New("invalid pairing recovery acknowledgment")
	}
	return r.withLock(func(snapshot *pairingOutcomeSnapshot) error {
		for i := range snapshot.Records {
			record := &snapshot.Records[i]
			if record.AttemptID != attemptID {
				continue
			}
			if record.Outcome != PairingOutcomeSuccess && record.Outcome != PairingOutcomeDenied {
				return errors.New("unresolved pairing recovery record cannot be acknowledged")
			}
			if record.AuditProof == nil {
				return errors.New("pairing completion audit has no independently durable evidence; operator reconciliation required")
			}
			if err := r.ensureCurrentSnapshotDurable(); err != nil {
				return fmt.Errorf("pairing recovery proof durability uncertain: %w", err)
			}
			if record.AcknowledgedAt != nil {
				return nil
			}
			now := time.Now().UTC()
			record.AcknowledgedAt = &now
			record.UpdatedAt = now
			return nil
		}
		return errors.New("pairing recovery attempt not found")
	})
}

// A snapshot may be readable after a failed post-replacement directory sync.
// Re-synchronize its exact inode and containing directory before treating
// recorded audit proof as durable. Ambiguous errors reject acknowledgment.
func (r *PairingRecovery) ensureCurrentSnapshotDurable() error {
	before, err := os.Lstat(r.path)
	if err != nil {
		return err
	}
	if err := trust.VerifyPairingStatePath(r.path); err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return errors.New("pairing recovery changed while synchronizing proof")
	}
	if err := f.Sync(); err != nil {
		return err
	}
	onPath, err := os.Lstat(r.path)
	if err != nil || !os.SameFile(opened, onPath) {
		return errors.New("pairing recovery replaced while synchronizing proof")
	}
	syncDir := syncAuditDirectory
	if r.syncDirectory != nil {
		syncDir = r.syncDirectory
	}
	return syncDir(filepath.Dir(r.path))
}

// Proof and authorized reconciliation must use the audit log belonging to
// this exact state root, never a caller-selected external audit file.
func (r *PairingRecovery) verifyPairingLogSource(log *Log) error {
	if r == nil || log == nil ||
		filepath.Clean(log.path) != filepath.Join(filepath.Dir(r.path), FileName) {
		return errors.New("pairing recovery audit source does not match protected state directory")
	}
	if err := trust.VerifyPairingStatePath(filepath.Dir(r.path)); err != nil {
		return fmt.Errorf("pairing recovery audit root is unsafe: %w", err)
	}
	return nil
}

// ConfirmCompletion independently re-reads the durably appended audit event
// under the rotating log lock, then retains a durable copy in the recovery
// register. A lost or ambiguous append never manufactures completion proof.
func (r *PairingRecovery) ConfirmCompletion(log *Log, attemptID string, event Event) error {
	if err := r.verifyPairingLogSource(log); err != nil {
		return err
	}
	if !pairingAttemptPattern.MatchString(attemptID) {
		return errors.New("invalid pairing audit confirmation")
	}
	if err := log.VerifyDurableEvent(event); err != nil {
		return fmt.Errorf("pairing audit event not independently verified: %w", err)
	}
	return r.recordAuditProof(attemptID, PairingAuditProof{
		Kind: "completion", Event: event, VerifiedAt: time.Now().UTC(),
	})
}

func (r *PairingRecovery) recordAuditProof(attemptID string, proof PairingAuditProof) error {
	return r.withLock(func(snapshot *pairingOutcomeSnapshot) error {
		for i := range snapshot.Records {
			record := &snapshot.Records[i]
			if record.AttemptID != attemptID {
				continue
			}
			if err := validatePairingProof(*record, proof); err != nil {
				return err
			}
			if record.AuditProof != nil {
				if *record.AuditProof != proof {
					return errors.New("conflicting immutable pairing audit proof")
				}
				return nil
			}
			record.AuditProof = &proof
			record.UpdatedAt = time.Now().UTC()
			return nil
		}
		return errors.New("pairing recovery attempt not found")
	})
}

// ReconcilePrivileged is an explicit locally privileged operator action.
// Readable trust alone is not an automatic reconciliation. The operator must
// have OS administrator/root authority, trust must match the exact recorded
// fingerprint, and the reconciliation must itself be audited and synchronized.
func (r *PairingRecovery) ReconcilePrivileged(log *Log, attemptID string) error {
	if err := r.verifyPairingLogSource(log); err != nil {
		return err
	}
	check := authorizePairingRecoveryOperator
	if r != nil && r.operatorCheck != nil {
		check = r.operatorCheck
	}
	if err := check(); err != nil {
		return fmt.Errorf("privileged pairing reconciliation denied: %w", err)
	}
	records, err := r.Records()
	if err != nil {
		return err
	}
	var record *PairingOutcome
	for i := range records {
		if records[i].AttemptID == attemptID {
			record = &records[i]
			break
		}
	}
	if record == nil || record.Outcome != PairingOutcomeSuccess || record.AuditProof != nil {
		return errors.New("reconciliation requires unresolved success record")
	}
	trustPath := filepath.Join(filepath.Dir(r.path), "trusted-clients.json")
	if err := trust.VerifyPairingStatePath(trustPath); err != nil {
		return fmt.Errorf("unsafe authoritative trust state: %w", err)
	}
	store, err := trust.Open(trustPath)
	if err != nil {
		return err
	}
	peer, found := store.Peers[record.PeerID]
	if !found || peer.Fingerprint != record.Fingerprint {
		return errors.New("authoritative trust does not confirm the exact pairing identity")
	}
	event := Event{
		Time: time.Now().UTC(), Type: "pairing.reconciliation", Outcome: "success",
		AttemptID: record.AttemptID, ActorID: record.ActorID, PeerID: record.PeerID,
		Reason: "privileged_trust_review",
	}
	if err := log.Append(event); err != nil {
		return fmt.Errorf("durable privileged reconciliation audit failed: %w", err)
	}
	if err := log.VerifyDurableEvent(event); err != nil {
		return err
	}
	return r.recordAuditProof(attemptID, PairingAuditProof{
		Kind: "reconciliation", Event: event, VerifiedAt: time.Now().UTC(),
	})
}

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
	AttemptID   string    `json:"attempt_id"`
	ActorID     string    `json:"actor_id"`
	PeerID      string    `json:"peer_id"`
	Fingerprint string    `json:"fingerprint"`
	Outcome     string    `json:"outcome"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type pairingOutcomeSnapshot struct {
	Version int              `json:"version"`
	Records []PairingOutcome `json:"records"`
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
	_, lockErr := os.Lstat(r.path + ".lock")
	if lockErr != nil && !errors.Is(lockErr, os.ErrNotExist) {
		return nil, lockErr
	}
	// Coordinate initial creation with every other process. The lock is
	// retained across restarts and is never removed by ordinary operation.
	unlock, err := lockFile(r.path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := trust.VerifyPairingStatePath(r.path + ".lock"); err != nil {
		return nil, err
	}
	_, stateErr := os.Lstat(r.path)
	if errors.Is(stateErr, os.ErrNotExist) {
		if lockErr == nil {
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
	if _, err := r.read(); err != nil {
		return nil, err
	}
	return r, nil
}

func validPairingOutcomeState(state string) bool {
	switch state {
	case PairingOutcomePending, PairingOutcomeSuccess, PairingOutcomeDenied, PairingOutcomeFailed, PairingOutcomeUncertain:
		return true
	}
	return false
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
	if err != nil {
		return err
	}
	if err := change(&snapshot); err != nil {
		return err
	}
	if err := validatePairingSnapshot(snapshot); err != nil {
		return err
	}
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
	if err != nil {
		return nil, err
	}
	return append([]PairingOutcome(nil), snapshot.Records...), nil
}

// Explicit operator action. Never remove pending, uncertain, or failed state.
func (r *PairingRecovery) AcknowledgeResolved(attemptID string) error {
	if !pairingAttemptPattern.MatchString(attemptID) {
		return errors.New("invalid pairing recovery acknowledgment")
	}
	return r.withLock(func(snapshot *pairingOutcomeSnapshot) error {
		for i, record := range snapshot.Records {
			if record.AttemptID == attemptID {
				if record.Outcome != PairingOutcomeSuccess && record.Outcome != PairingOutcomeDenied {
					return errors.New("unresolved pairing recovery record cannot be deleted")
				}
				snapshot.Records = append(snapshot.Records[:i], snapshot.Records[i+1:]...)
				return nil
			}
		}
		return errors.New("pairing recovery attempt not found")
	})
}

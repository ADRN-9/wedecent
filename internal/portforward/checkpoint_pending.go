package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const checkpointPendingVersion = 1
const checkpointPendingMaxSize = 16 << 20
const checkpointPendingMaxEntries = 65536

var ErrCheckpointHistorical = errors.New("portforward: historical checkpoint receipt cannot initiate a new operation")

type checkpointPendingEntry struct {
	Fingerprint      string                 `json:"fingerprint"`
	State            string                 `json:"state"`
	CreatedAt        int64                  `json:"created_at_unix_ms"`
	ReceiptHash      string                 `json:"receipt_hash,omitempty"`
	Acknowledgements []CheckpointWitnessAck `json:"acknowledgements,omitempty"`
}

type checkpointPendingSnapshot struct {
	Version int                               `json:"version"`
	Entries map[string]checkpointPendingEntry `json:"entries"`
}

// CheckpointPendingStore persists client intent; it is not replay authority.
type CheckpointPendingStore interface {
	Begin(context.Context, CheckpointRequest) (existingPending bool, err error)
	Resolve(context.Context, CheckpointRequest, CheckpointReceipt) error
}

type checkpointPendingAcknowledgements interface {
	RecordAcknowledgement(context.Context, CheckpointRequest, CheckpointReceipt, CheckpointWitnessAck, CheckpointWitnessTrust) error
	LoadAcknowledgements(context.Context, CheckpointRequest, CheckpointReceipt, []CheckpointWitnessTrust) ([]CheckpointWitnessAck, error)
}

type checkpointPendingCompactor interface {
	Compact(context.Context, []CheckpointWitnessAck, []CheckpointWitnessTrust, int) error
}

type FileCheckpointPendingStore struct {
	Path string
	Now  func() time.Time

	// writeSnapshot is a deterministic persistence fault-injection seam for package tests.
	writeSnapshot func(string, any, string, int64) error
}

func NewFileCheckpointPendingStore(path string) (*FileCheckpointPendingStore, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return nil, ErrReplayUnavailable
	}
	if err := prepareReplayDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%w: pending directory: %v", ErrReplayUnavailable, err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, ErrReplayUnavailable
		}
		if err := secureReplayFile(path); err != nil {
			return nil, fmt.Errorf("%w: pending store permissions: %v", ErrReplayUnavailable, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: inspect pending store: %v", ErrReplayUnavailable, err)
	}
	return &FileCheckpointPendingStore{Path: path}, nil
}

func (s *FileCheckpointPendingStore) Begin(ctx context.Context, request CheckpointRequest) (bool, error) {
	if s == nil || ctx == nil || s.Path == "" {
		return false, ErrReplayUnavailable
	}
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return false, err
	}
	key := checkpointPendingKey(request)
	if key == "" {
		return false, ErrCheckpointIntegrity
	}
	return s.update(ctx, func(snapshot *checkpointPendingSnapshot) (bool, error) {
		if old, ok := snapshot.Entries[key]; ok {
			if old.Fingerprint != hex.EncodeToString(fingerprint[:]) {
				return false, ErrCheckpointConflict
			}
			if old.State == "pending" || old.State == "resolved" {
				return true, nil
			}
			return false, ErrReplayUnavailable
		}
		now := time.Now().UTC()
		if s.Now != nil {
			now = s.Now().UTC()
		}
		if now.IsZero() {
			return false, ErrReplayUnavailable
		}
		snapshot.Entries[key] = checkpointPendingEntry{Fingerprint: hex.EncodeToString(fingerprint[:]), State: "pending", CreatedAt: now.UnixMilli()}
		return false, nil
	})
}

func (s *FileCheckpointPendingStore) Resolve(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt) error {
	if s == nil || ctx == nil || s.Path == "" {
		return ErrReplayUnavailable
	}
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return err
	}
	if receipt.RequestSHA256 != fingerprint || receipt.JTI != request.JTI {
		return ErrCheckpointIntegrity
	}
	_, err = s.update(ctx, func(snapshot *checkpointPendingSnapshot) (bool, error) {
		key := checkpointPendingKey(request)
		entry, ok := snapshot.Entries[key]
		if !ok || entry.Fingerprint != hex.EncodeToString(fingerprint[:]) {
			return false, ErrCheckpointHistorical
		}
		receiptHash := CheckpointReceiptDigest(receipt)
		if entry.State == "resolved" {
			if entry.ReceiptHash == receiptHash {
				return false, nil
			}
			return false, ErrCheckpointConflict
		}
		if entry.State != "pending" {
			return false, ErrCheckpointHistorical
		}
		entry.State = "resolved"
		entry.ReceiptHash = receiptHash
		snapshot.Entries[key] = entry
		return false, nil
	})
	return err
}

func (s *FileCheckpointPendingStore) RecordAcknowledgement(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, ack CheckpointWitnessAck, trust CheckpointWitnessTrust) error {
	if s == nil || ctx == nil {
		return ErrReplayUnavailable
	}
	return recordCheckpointAcknowledgement(ctx, request, receipt, ack, trust, func(change func(*checkpointPendingSnapshot) (bool, error)) error {
		_, err := s.update(ctx, change)
		return err
	})
}

func (s *FileCheckpointPendingStore) LoadAcknowledgements(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, witnesses []CheckpointWitnessTrust) ([]CheckpointWitnessAck, error) {
	if s == nil || ctx == nil {
		return nil, ErrReplayUnavailable
	}
	var snapshot checkpointPendingSnapshot
	_, err := s.update(ctx, func(current *checkpointPendingSnapshot) (bool, error) {
		snapshot = *current
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return validateStoredCheckpointAcknowledgements(snapshot, request, receipt, witnesses)
}

func recordCheckpointAcknowledgement(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, ack CheckpointWitnessAck, trust CheckpointWitnessTrust, update func(func(*checkpointPendingSnapshot) (bool, error)) error) error {
	fp, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return err
	}
	rh := CheckpointReceiptDigest(receipt)
	if receipt.RequestSHA256 != fp || receipt.JTI != request.JTI ||
		VerifyCheckpointWitnessAck(ack, trust.ID, trust.PublicKey) != nil ||
		ack.Scope != witnessScope(checkpointEndpointForConsumer(request)) ||
		ack.JTI != request.JTI || ack.RequestSHA256 != fp ||
		ack.PrimaryReceiptSHA256 != sha256.Sum256(checkpointReceiptMessage(receipt)) {
		return ErrCheckpointIntegrity
	}
	return update(func(snapshot *checkpointPendingSnapshot) (bool, error) {
		key := checkpointPendingKey(request)
		entry, ok := snapshot.Entries[key]
		if !ok || entry.Fingerprint != hex.EncodeToString(fp[:]) ||
			entry.State != "resolved" || entry.ReceiptHash != rh {
			return false, ErrCheckpointHistorical
		}
		for _, old := range entry.Acknowledgements {
			if old.WitnessID != ack.WitnessID {
				continue
			}
			if old.Scope != ack.Scope || old.JTI != ack.JTI ||
				old.RequestSHA256 != ack.RequestSHA256 ||
				old.PrimaryReceiptSHA256 != ack.PrimaryReceiptSHA256 ||
				old.WitnessKeyID != ack.WitnessKeyID {
				return false, ErrCheckpointConflict
			}
			return false, nil
		}
		entry.Acknowledgements = append(entry.Acknowledgements, ack)
		snapshot.Entries[key] = entry
		return false, nil
	})
}

func validateStoredCheckpointAcknowledgements(snapshot checkpointPendingSnapshot, request CheckpointRequest, receipt CheckpointReceipt, witnesses []CheckpointWitnessTrust) ([]CheckpointWitnessAck, error) {
	fp, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return nil, err
	}
	rh := CheckpointReceiptDigest(receipt)
	if receipt.RequestSHA256 != fp || receipt.JTI != request.JTI {
		return nil, ErrCheckpointIntegrity
	}
	key := checkpointPendingKey(request)
	entry, ok := snapshot.Entries[key]
	if !ok || entry.Fingerprint != hex.EncodeToString(fp[:]) ||
		entry.State != "resolved" || entry.ReceiptHash != rh {
		return nil, ErrCheckpointHistorical
	}
	trusted := make(map[string]CheckpointWitnessTrust, len(witnesses))
	for _, trust := range witnesses {
		trusted[trust.ID] = trust
	}
	seen := make(map[string]bool, len(entry.Acknowledgements))
	acks := make([]CheckpointWitnessAck, 0, len(entry.Acknowledgements))
	for _, ack := range entry.Acknowledgements {
		trust, ok := trusted[ack.WitnessID]
		if !ok || seen[ack.WitnessID] ||
			VerifyCheckpointWitnessAck(ack, trust.ID, trust.PublicKey) != nil ||
			ack.Scope != witnessScope(checkpointEndpointForConsumer(request)) ||
			ack.JTI != request.JTI || ack.RequestSHA256 != fp ||
			ack.PrimaryReceiptSHA256 != sha256.Sum256(checkpointReceiptMessage(receipt)) {
			return nil, ErrCheckpointIntegrity
		}
		seen[ack.WitnessID] = true
		acks = append(acks, ack)
	}
	return acks, nil
}

func (s *MemoryCheckpointPendingStore) RecordAcknowledgement(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, ack CheckpointWitnessAck, trust CheckpointWitnessTrust) error {
	if s == nil || ctx == nil {
		return ErrReplayUnavailable
	}
	return recordCheckpointAcknowledgement(ctx, request, receipt, ack, trust, func(change func(*checkpointPendingSnapshot) (bool, error)) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.entries == nil {
			s.entries = make(map[string]checkpointPendingEntry)
		}
		snapshot := checkpointPendingSnapshot{Version: checkpointPendingVersion, Entries: s.entries}
		_, err := change(&snapshot)
		s.entries = snapshot.Entries
		return err
	})
}

func (s *MemoryCheckpointPendingStore) LoadAcknowledgements(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, witnesses []CheckpointWitnessTrust) ([]CheckpointWitnessAck, error) {
	if s == nil || ctx == nil {
		return nil, ErrReplayUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return validateStoredCheckpointAcknowledgements(checkpointPendingSnapshot{
		Version: checkpointPendingVersion,
		Entries: s.entries,
	}, request, receipt, witnesses)
}

func (s *FileCheckpointPendingStore) Compact(ctx context.Context, acknowledgements []CheckpointWitnessAck, witnesses []CheckpointWitnessTrust, quorum int) error {
	if s == nil || ctx == nil || !validWitnessSet(witnesses, quorum) {
		return ErrReplayUnavailable
	}
	_, err := s.update(ctx, func(snapshot *checkpointPendingSnapshot) (bool, error) {
		compactAcknowledgedPendingEntries(snapshot, acknowledgements, witnesses, quorum)
		return false, nil
	})
	return err
}

func (s *FileCheckpointPendingStore) update(ctx context.Context, change func(*checkpointPendingSnapshot) (bool, error)) (existing bool, resultErr error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := secureReplayDirectory(filepath.Dir(s.Path)); err != nil {
		return false, fmt.Errorf("%w: pending directory: %v", ErrReplayUnavailable, err)
	}
	unlock, _, err := lockReplayFile(s.Path)
	if err != nil {
		return false, fmt.Errorf("%w: lock pending store: %v", ErrReplayUnavailable, err)
	}
	defer func() {
		if unlockErr := unlock(); unlockErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("%w: unlock pending store: %v", ErrReplayUnavailable, unlockErr))
		}
	}()
	snapshot := checkpointPendingSnapshot{Version: checkpointPendingVersion, Entries: map[string]checkpointPendingEntry{}}
	data, err := readReplayJSON(s.Path, checkpointPendingMaxSize)
	if err == nil {
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&snapshot); err != nil {
			return false, fmt.Errorf("%w: decode pending store: %v", ErrReplayUnavailable, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return false, ErrReplayUnavailable
		}
		if snapshot.Version != checkpointPendingVersion || snapshot.Entries == nil || len(snapshot.Entries) > checkpointPendingMaxEntries {
			return false, ErrReplayUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("%w: read pending store: %v", ErrReplayUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	existing, err = change(&snapshot)
	if err != nil {
		return false, err
	}
	if len(snapshot.Entries) > checkpointPendingMaxEntries {
		return false, ErrReplayUnavailable
	}
	write := writeReplayJSON
	if s.writeSnapshot != nil {
		write = s.writeSnapshot
	}
	if err := write(s.Path, snapshot, replayStagingPattern(s.Path, "pendingops"), checkpointPendingMaxSize); err != nil {
		return false, fmt.Errorf("%w: persist pending operation: %v", ErrReplayUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return existing, nil
}

func (s *MemoryCheckpointPendingStore) Compact(ctx context.Context, acknowledgements []CheckpointWitnessAck, witnesses []CheckpointWitnessTrust, quorum int) error {
	if s == nil || ctx == nil || !validWitnessSet(witnesses, quorum) {
		return ErrReplayUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.entries == nil {
		return nil
	}
	snapshot := checkpointPendingSnapshot{Version: checkpointPendingVersion, Entries: s.entries}
	compactAcknowledgedPendingEntries(&snapshot, acknowledgements, witnesses, quorum)
	s.entries = snapshot.Entries
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func compactAcknowledgedPendingEntries(snapshot *checkpointPendingSnapshot, acknowledgements []CheckpointWitnessAck, witnesses []CheckpointWitnessTrust, quorum int) {
	// The caller's slice is not durable evidence. Only acknowledgements already
	// persisted in this exact journal entry can authorize its removal.
	_ = acknowledgements
	trusted := make(map[string]ed25519.PublicKey, len(witnesses))
	for _, witness := range witnesses {
		trusted[witness.ID] = witness.PublicKey
	}
	for key, entry := range snapshot.Entries {
		if entry.State != "resolved" || entry.Fingerprint == "" || entry.ReceiptHash == "" {
			continue
		}
		fingerprint, err := hex.DecodeString(entry.Fingerprint)
		if err != nil || len(fingerprint) != sha256.Size {
			continue
		}
		receiptHash, err := hex.DecodeString(entry.ReceiptHash)
		if err != nil || len(receiptHash) != sha256.Size {
			continue
		}
		seen := make(map[string]bool, quorum)
		for _, ack := range entry.Acknowledgements {
			publicKey := trusted[ack.WitnessID]
			if seen[ack.WitnessID] ||
				VerifyCheckpointWitnessAck(ack, ack.WitnessID, publicKey) != nil {
				continue
			}
			expectedKey := ack.Scope.DeviceID + "|" + ack.Scope.AccountID + "|" + ack.Scope.OrganizationID + "|" + ack.JTI
			if expectedKey != key || !bytesEqual(ack.RequestSHA256[:], fingerprint) ||
				!bytesEqual(ack.PrimaryReceiptSHA256[:], receiptHash) {
				continue
			}
			seen[ack.WitnessID] = true
		}
		if len(seen) >= quorum {
			delete(snapshot.Entries, key)
		}
	}
}

func checkpointPendingKey(request CheckpointRequest) string {
	endpoint, ok := checkpointConsumer(request)
	if !ok {
		return ""
	}
	return endpoint.DeviceID + "|" + endpoint.AccountID + "|" + endpoint.OrganizationID + "|" + request.JTI
}

// MemoryCheckpointPendingStore is test-only and provides no crash durability.
type MemoryCheckpointPendingStore struct {
	entries map[string]checkpointPendingEntry
}

func NewMemoryCheckpointPendingStore() *MemoryCheckpointPendingStore {
	return &MemoryCheckpointPendingStore{entries: make(map[string]checkpointPendingEntry)}
}

func (s *MemoryCheckpointPendingStore) Begin(ctx context.Context, request CheckpointRequest) (bool, error) {
	if s == nil || ctx == nil {
		return false, ErrReplayUnavailable
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	fp, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return false, err
	}
	key := checkpointPendingKey(request)
	if key == "" {
		return false, ErrCheckpointIntegrity
	}
	if s.entries == nil {
		s.entries = make(map[string]checkpointPendingEntry)
	}
	if old, ok := s.entries[key]; ok {
		if old.Fingerprint != hex.EncodeToString(fp[:]) {
			return false, ErrCheckpointConflict
		}
		if old.State == "pending" || old.State == "resolved" {
			return true, nil
		}
		return false, ErrReplayUnavailable
	}
	if len(s.entries) >= checkpointPendingMaxEntries {
		return false, ErrReplayUnavailable
	}
	s.entries[key] = checkpointPendingEntry{Fingerprint: hex.EncodeToString(fp[:]), State: "pending"}
	return false, nil
}

func (s *MemoryCheckpointPendingStore) Resolve(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt) error {
	if s == nil || ctx == nil {
		return ErrReplayUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fp, err := CheckpointRequestFingerprint(request)
	if err != nil || receipt.RequestSHA256 != fp || receipt.JTI != request.JTI {
		return ErrCheckpointIntegrity
	}
	key := checkpointPendingKey(request)
	entry, ok := s.entries[key]
	if !ok || entry.Fingerprint != hex.EncodeToString(fp[:]) {
		return ErrCheckpointHistorical
	}
	receiptHash := CheckpointReceiptDigest(receipt)
	if entry.State == "resolved" {
		if entry.ReceiptHash == receiptHash {
			return nil
		}
		return ErrCheckpointConflict
	}
	if entry.State != "pending" {
		return ErrCheckpointHistorical
	}
	entry.State = "resolved"
	entry.ReceiptHash = receiptHash
	s.entries[key] = entry
	return nil
}

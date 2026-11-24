package portforward

import (
	"context"
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

var ErrCheckpointHistorical = errors.New("portforward: historical checkpoint receipt cannot initiate a new operation")

type checkpointPendingEntry struct {
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
	CreatedAt   int64  `json:"created_at_unix_ms"`
	ReceiptHash string `json:"receipt_hash,omitempty"`
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

type FileCheckpointPendingStore struct {
	Path string
	Now  func() time.Time
}

func NewFileCheckpointPendingStore(path string) (*FileCheckpointPendingStore, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return nil, ErrReplayUnavailable
	}
	if err := secureReplayDirectory(filepath.Dir(path)); err != nil {
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
			if old.State != "pending" {
				return false, ErrCheckpointReplay
			}
			return true, nil
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
		if !ok || entry.State != "pending" || entry.Fingerprint != hex.EncodeToString(fingerprint[:]) {
			return false, ErrCheckpointHistorical
		}
		entry.State = "resolved"
		entry.ReceiptHash = CheckpointReceiptDigest(receipt)
		snapshot.Entries[key] = entry
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
		if snapshot.Version != checkpointPendingVersion || snapshot.Entries == nil {
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
	if err := writeReplayJSON(s.Path, snapshot, replayStagingPattern(s.Path, "pendingops"), checkpointPendingMaxSize); err != nil {
		return false, fmt.Errorf("%w: persist pending operation: %v", ErrReplayUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return existing, nil
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
		if old.State != "pending" {
			return false, ErrCheckpointReplay
		}
		return true, nil
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
	if !ok || entry.State != "pending" || entry.Fingerprint != hex.EncodeToString(fp[:]) {
		return ErrCheckpointHistorical
	}
	entry.State = "resolved"
	entry.ReceiptHash = CheckpointReceiptDigest(receipt)
	s.entries[key] = entry
	return nil
}

package updateinfo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	UpdateStateVersion           = 1
	UpdateStateVersionWithKeyset = 2
	UpdateStateFilename          = "update-state.json"
	MaxUpdateStateBytes          = 4 << 10
)

var ErrInvalidState = errors.New("updateinfo: invalid update state")

// State is deliberately minimal and non-secret. StableSequence is the highest
// signed stable-channel sequence explicitly accepted after a successful update
// boundary; merely fetching a manifest must not advance it.
type State struct {
	Version        int    `json:"version"`
	StableSequence uint64 `json:"stable_sequence"`
	KeysetEpoch    uint64 `json:"keyset_epoch,omitempty"`
	KeysetDigest   string `json:"keyset_digest,omitempty"`
	PendingInstall *InstallTransaction `json:"pending_install,omitempty"`
}

type StateStore struct {
	Path string
	mu   sync.Mutex
}

func NewStateStore(path string) *StateStore {
	return &StateStore{Path: path}
}

func StatePath(stateDir string) string {
	return filepath.Join(stateDir, UpdateStateFilename)
}

// Load returns sequence zero when no state has ever been committed.
func (s *StateStore) Load() (State, error) {
	if s == nil || s.Path == "" {
		return State{}, fmt.Errorf("%w: state path is required", ErrInvalidState)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return loadState(s.Path)
}

// Advance atomically commits a strictly newer accepted stable-channel
// sequence. It never permits a caller to reset or decrease anti-rollback state.
func (s *StateStore) Advance(sequence uint64) error {
	if s == nil || s.Path == "" {
		return fmt.Errorf("%w: state path is required", ErrInvalidState)
	}
	if sequence == 0 {
		return fmt.Errorf("%w: sequence must be positive", ErrInvalidState)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := acquireUpdateLock(context.Background(), s.Path)
	if err != nil {
		return err
	}
	defer release()
	current, err := loadState(s.Path)
	if err != nil {
		return err
	}
	if sequence <= current.StableSequence {
		return fmt.Errorf("%w: sequence %d is not newer than %d", ErrRollback, sequence, current.StableSequence)
	}
	next := State{
		Version:        current.Version,
		StableSequence: sequence,
		KeysetEpoch:    current.KeysetEpoch,
		KeysetDigest:   current.KeysetDigest,
	}
	if next.Version == 0 {
		next.Version = UpdateStateVersion
	}
	return saveState(s.Path, next)
}

// VerifyAndAdvanceKeyset authenticates a root-signed keyset against the
// persisted epoch/digest and commits a newer keyset atomically with the current
// stable sequence. Callers cannot advance trust state using an unverified digest.
func (s *StateStore) VerifyAndAdvanceKeyset(
	ctx context.Context,
	rootKeyID string,
	rootPublicKey ed25519.PublicKey,
	keysetBytes, signatureBytes []byte,
	now time.Time,
) (VerifiedKeyset, error) {
	var zero VerifiedKeyset
	if s == nil || s.Path == "" {
		return zero, fmt.Errorf("%w: state path is required", ErrInvalidState)
	}
	if ctx == nil {
		return zero, fmt.Errorf("%w: context is required", ErrInvalidState)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := acquireUpdateLock(ctx, s.Path)
	if err != nil {
		return zero, err
	}
	defer release()
	current, err := loadState(s.Path)
	if err != nil {
		return zero, err
	}
	verified, err := VerifyKeyset(
		rootKeyID, rootPublicKey, keysetBytes, signatureBytes, now,
		current.KeysetEpoch, current.KeysetDigest,
	)
	if err != nil {
		return zero, err
	}
	if verified.Epoch() == current.KeysetEpoch {
		return verified, nil
	}
	next := State{
		Version:        UpdateStateVersionWithKeyset,
		StableSequence: current.StableSequence,
		KeysetEpoch:    verified.Epoch(),
		KeysetDigest:   verified.Digest(),
	}
	if err := saveState(s.Path, next); err != nil {
		return zero, fmt.Errorf("%w: persist verified keyset: %v", ErrInvalidState, err)
	}
	return verified, nil
}

func loadState(path string) (State, error) {
	var zero State
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			dir := filepath.Dir(path)
			dirInfo, dirErr := os.Lstat(dir)
			if dirErr == nil {
				if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
					return zero, fmt.Errorf("%w: update state parent must be a real directory", ErrInvalidState)
				}
				if err := validateStateDirInfo(dir, dirInfo); err != nil {
					return zero, err
				}
			} else if errors.Is(dirErr, os.ErrNotExist) {
				if err := validateStateDirAncestors(dir); err != nil {
					return zero, err
				}
			} else {
				return zero, fmt.Errorf("%w: stat update state parent: %v", ErrInvalidState, dirErr)
			}
			return State{Version: UpdateStateVersion}, nil
		}
		return zero, fmt.Errorf("%w: stat update state: %v", ErrInvalidState, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return zero, fmt.Errorf("%w: update state must not be a symbolic link", ErrInvalidState)
	}
	if !info.Mode().IsRegular() {
		return zero, fmt.Errorf("%w: update state must be a regular file", ErrInvalidState)
	}
	dir := filepath.Dir(path)
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return zero, fmt.Errorf("%w: update state parent must be a real directory", ErrInvalidState)
	}
	if err := validateStateDirInfo(dir, dirInfo); err != nil {
		return zero, err
	}
	if err := validateStateFileInfo(path, info); err != nil {
		return zero, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("%w: read update state: %v", ErrInvalidState, err)
	}
	if len(data) == 0 || len(data) > MaxUpdateStateBytes {
		return zero, fmt.Errorf("%w: update state size is invalid", ErrInvalidState)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return zero, fmt.Errorf("%w: decode update state: %v", ErrInvalidState, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return zero, fmt.Errorf("%w: multiple JSON values", ErrInvalidState)
		}
		return zero, fmt.Errorf("%w: trailing data: %v", ErrInvalidState, err)
	}
	if err := state.validatePersisted(); err != nil {
		return zero, err
	}
	canonical, err := encodeState(state)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(data, canonical) {
		return zero, fmt.Errorf("%w: update state is not canonical", ErrInvalidState)
	}
	return state, nil
}

func saveState(path string, state State) error {
	if err := state.validatePersisted(); err != nil {
		return err
	}
	data, err := encodeState(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := ensurePrivateStateDir(dir); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".update-state-*")
	if err != nil {
		return fmt.Errorf("%w: create update state temp file: %v", ErrInvalidState, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("%w: protect update state temp file: %v", ErrInvalidState, err)
	}
	tempInfo, err := tmp.Stat()
	if err != nil {
		cleanup()
		return fmt.Errorf("%w: inspect update state temp file: %v", ErrInvalidState, err)
	}
	if err := validateStateFileInfo(tmpPath, tempInfo); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("%w: write update state: %v", ErrInvalidState, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("%w: sync update state: %v", ErrInvalidState, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("%w: close update state: %v", ErrInvalidState, err)
	}
	if err := replaceStateFile(tmpPath, path, dir); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func (s State) validatePersisted() error {
	if s.PendingInstall != nil {
		if err := s.PendingInstall.validate(); err != nil { return err }
		if s.Version != UpdateStateVersionWithKeyset { return fmt.Errorf("%w: pending install requires keyset state", ErrInvalidState) }
	}
	switch s.Version {
	case UpdateStateVersion:
		if s.StableSequence == 0 || s.KeysetEpoch != 0 || s.KeysetDigest != "" {
			return fmt.Errorf("%w: legacy state fields are invalid", ErrInvalidState)
		}
	case UpdateStateVersionWithKeyset:
		if s.KeysetEpoch == 0 || len(s.KeysetDigest) != 64 || strings.ToLower(s.KeysetDigest) != s.KeysetDigest {
			return fmt.Errorf("%w: version 2 keyset epoch or digest is invalid", ErrInvalidState)
		}
		if _, err := hex.DecodeString(s.KeysetDigest); err != nil {
			return fmt.Errorf("%w: keyset digest is invalid", ErrInvalidState)
		}
	default:
		return fmt.Errorf("%w: unsupported state version %d", ErrInvalidState, s.Version)
	}
	return nil
}

func encodeState(state State) ([]byte, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("%w: encode update state: %v", ErrInvalidState, err)
	}
	data = append(data, '\n')
	if len(data) > MaxUpdateStateBytes {
		return nil, fmt.Errorf("%w: update state exceeds %d bytes", ErrInvalidState, MaxUpdateStateBytes)
	}
	return data, nil
}

func ensurePrivateStateDir(dir string) error {
	if err := validateStateDirAncestors(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: create update state directory: %v", ErrInvalidState, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: stat update state directory: %v", ErrInvalidState, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: update state directory must be a real directory", ErrInvalidState)
	}
	if err := validateStateDirInfo(dir, info); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("%w: protect update state directory: %v", ErrInvalidState, err)
	}
	return nil
}

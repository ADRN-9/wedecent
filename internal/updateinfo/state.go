package updateinfo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	UpdateStateVersion  = 1
	UpdateStateFilename = "update-state.json"
	MaxUpdateStateBytes = 4 << 10
)

var ErrInvalidState = errors.New("updateinfo: invalid update state")

// State is deliberately minimal and non-secret. StableSequence is the highest
// signed stable-channel sequence explicitly accepted after a successful update
// boundary; merely fetching a manifest must not advance it.
type State struct {
	Version        int    `json:"version"`
	StableSequence uint64 `json:"stable_sequence"`
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
	current, err := loadState(s.Path)
	if err != nil {
		return err
	}
	if sequence <= current.StableSequence {
		return fmt.Errorf("%w: sequence %d is not newer than %d", ErrRollback, sequence, current.StableSequence)
	}
	return saveState(s.Path, State{Version: UpdateStateVersion, StableSequence: sequence})
}

func loadState(path string) (State, error) {
	var zero State
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
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
	if err := validateStateFileInfo(info); err != nil {
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
	if s.Version != UpdateStateVersion {
		return fmt.Errorf("%w: unsupported state version %d", ErrInvalidState, s.Version)
	}
	if s.StableSequence == 0 {
		return fmt.Errorf("%w: persisted sequence must be positive", ErrInvalidState)
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
	if err := validateStateDirInfo(info); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("%w: protect update state directory: %v", ErrInvalidState, err)
	}
	return nil
}

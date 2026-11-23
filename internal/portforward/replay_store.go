package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

const (
	replayStoreVersion       = 2
	legacyReplayStoreVersion = 1
	maxReplayStoreSize = 16 << 20
	defaultReplayLimit = 100000
)

type replaySnapshot struct {
	Version    int              `json:"version"`
	DeviceID   string           `json:"device_id"`
	Generation uint64           `json:"generation"`
	Entries    map[string]int64 `json:"entries"`
}

type replayAnchor struct {
	Version    int    `json:"version"`
	DeviceID   string `json:"device_id"`
	Generation uint64 `json:"generation"`
}

// FileReplay provides cross-process, durable, device-scoped single-use JTI
// consumption. Use a distinct file and local device ID at each endpoint.
type FileReplay struct {
	Path       string
	DeviceID   mesh.DeviceID
	MaxEntries int
	Now        func() time.Time
}

func NewFileReplay(path string, deviceID mesh.DeviceID) (*FileReplay, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) || !deviceIDPattern.MatchString(string(deviceID)) {
		return nil, ErrReplayUnavailable
	}
	return &FileReplay{
		Path: path, DeviceID: deviceID, MaxEntries: defaultReplayLimit,
	}, nil
}

// NewPersistentAuthorizationVerifier constructs a verifier with durable replay
// storage scoped to one endpoint identity. The public key is not secret.
func NewPersistentAuthorizationVerifier(path string, localDeviceID mesh.DeviceID, publicKey ed25519.PublicKey) (*AuthorizationVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrAuthorizationInvalid
	}
	replay, err := NewFileReplay(path, localDeviceID)
	if err != nil {
		return nil, err
	}
	return &AuthorizationVerifier{
		PublicKey: append(ed25519.PublicKey(nil), publicKey...),
		Replay:    replay,
	}, nil
}

func (r *FileReplay) ConsumePortForwardAuthorization(ctx context.Context, jti string, expiresAt time.Time) error {
	if ctx == nil {
		return ErrAuthorizationInvalid
	}
	if r == nil || !deviceIDPattern.MatchString(string(r.DeviceID)) || r.Path == "" {
		return ErrReplayUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !jtiPattern.MatchString(jti) {
		return ErrAuthorizationInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(jti)
	if err != nil || len(raw) != 16 || base64.RawURLEncoding.EncodeToString(raw) != jti {
		return ErrAuthorizationInvalid
	}

	now := replayStoreNow(r)
	if !expiresAt.After(now) {
		return ErrAuthorizationExpired
	}
	if expiresAt.Sub(now) > MaxAuthorizationLifetime {
		return ErrAuthorizationInvalid
	}
	limit := r.MaxEntries
	if limit == 0 {
		limit = defaultReplayLimit
	}
	if limit < 1 || limit > defaultReplayLimit {
		return ErrReplayUnavailable
	}

	unlock, createdLock, err := lockReplayFile(r.Path)
	if err != nil {
		return fmt.Errorf("%w: lock replay store: %v", ErrReplayUnavailable, err)
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	now = replayStoreNow(r)
	if !expiresAt.After(now) {
		return ErrAuthorizationExpired
	}
	if expiresAt.Sub(now) > MaxAuthorizationLifetime {
		return ErrAuthorizationInvalid
	}

	snapshot, err := loadReplaySnapshot(r.Path, r.DeviceID, createdLock)
	if err != nil {
		return fmt.Errorf("%w: read replay store: %v", ErrReplayUnavailable, err)
	}
	entries := snapshot.Entries
	nowMS := now.UnixMilli()
	for key, expiryMS := range entries {
		if expiryMS <= nowMS {
			delete(entries, key)
			continue
		}
		if expiryMS-nowMS > MaxAuthorizationLifetime.Milliseconds() {
			return ErrReplayUnavailable
		}
	}
	if _, exists := entries[jti]; exists {
		return ErrAuthorizationReplay
	}
	if len(entries) >= limit {
		return ErrReplayUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if snapshot.Generation == ^uint64(0) {
		return ErrReplayUnavailable
	}
	entries[jti] = expiresAt.UTC().UnixMilli()
	nextGeneration := snapshot.Generation + 1
	anchor := replayAnchor{Version: replayStoreVersion, DeviceID: string(r.DeviceID), Generation: nextGeneration}
	// Persist the monotonic anchor first. A crash can make the store unavailable,
	// but cannot silently accept an older replay snapshot.
	if err := writeReplayAnchor(r.Path+".anchor", anchor); err != nil {
		return fmt.Errorf("%w: persist replay anchor: %v", ErrReplayUnavailable, err)
	}
	if err := writeReplayEntries(r.Path, r.DeviceID, nextGeneration, entries); err != nil {
		return fmt.Errorf("%w: persist replay consumption: %v", ErrReplayUnavailable, err)
	}
	return nil
}

func loadReplaySnapshot(path string, deviceID mesh.DeviceID, createdLock bool) (replaySnapshot, error) {
	anchorPath := path + ".anchor"
	anchor, anchorErr := readReplayAnchor(anchorPath, deviceID)
	if anchorErr == nil {
		snapshot, err := readReplaySnapshot(path, deviceID)
		if err != nil {
			return replaySnapshot{}, err
		}
		if snapshot.Version != replayStoreVersion {
			return replaySnapshot{}, errors.New("replay state version does not match protected anchor")
		}
		if snapshot.Generation != anchor.Generation {
			return replaySnapshot{}, errors.New("replay state generation does not match protected anchor")
		}
		return snapshot, nil
	}
	if !errors.Is(anchorErr, os.ErrNotExist) {
		return replaySnapshot{}, anchorErr
	}

	// Existing C93 stores are anchored on first C94 use. Missing state or lock
	// files after initialization are rejected by the platform lock helper.
	if !createdLock {
		snapshot, err := readReplaySnapshot(path, deviceID)
		if err != nil || snapshot.Version != legacyReplayStoreVersion {
			return replaySnapshot{}, errors.New("replay anchor is missing for a non-legacy store")
		}
		snapshot.Version = replayStoreVersion
		anchor := replayAnchor{Version: replayStoreVersion, DeviceID: string(deviceID), Generation: snapshot.Generation}
		if err := writeReplayAnchor(anchorPath, anchor); err != nil {
			return replaySnapshot{}, err
		}
		return snapshot, nil
	}
	if _, err := os.Lstat(path); err == nil {
		return replaySnapshot{}, errors.New("replay lock was recreated for an existing state file")
	} else if !errors.Is(err, os.ErrNotExist) {
		return replaySnapshot{}, err
	}
	return replaySnapshot{Version: replayStoreVersion, DeviceID: string(deviceID), Entries: make(map[string]int64)}, nil
}

func readReplayAnchor(path string, deviceID mesh.DeviceID) (replayAnchor, error) {
	data, err := readReplayJSON(path, 4096)
	if err != nil {
		return replayAnchor{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var anchor replayAnchor
	if err := decoder.Decode(&anchor); err != nil {
		return replayAnchor{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return replayAnchor{}, errors.New("replay anchor contains trailing JSON")
		}
		return replayAnchor{}, err
	}
	if anchor.Version != replayStoreVersion || anchor.DeviceID != string(deviceID) {
		return replayAnchor{}, errors.New("replay anchor scope or version mismatch")
	}
	return anchor, nil
}

func readReplaySnapshot(path string, deviceID mesh.DeviceID) (replaySnapshot, error) {
	data, err := readReplayJSON(path, maxReplayStoreSize)
	if err != nil {
		return replaySnapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot replaySnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return replaySnapshot{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return replaySnapshot{}, errors.New("replay store contains trailing JSON")
		}
		return replaySnapshot{}, err
	}
	if snapshot.Version != replayStoreVersion && snapshot.Version != legacyReplayStoreVersion ||
		snapshot.DeviceID != string(deviceID) || snapshot.Entries == nil || len(snapshot.Entries) > defaultReplayLimit {
		return replaySnapshot{}, errors.New("replay store scope or version mismatch")
	}
	for jti, expiryMS := range snapshot.Entries {
		if !jtiPattern.MatchString(jti) || expiryMS <= 0 {
			return replaySnapshot{}, errors.New("replay store contains invalid entry")
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(jti)
		if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != jti {
			return replaySnapshot{}, errors.New("replay store contains invalid JTI")
		}
	}
	return snapshot, nil
}

func readReplayJSON(path string, maxSize int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxSize {
		return nil, errors.New("replay metadata is not a bounded regular file")
	}
	if err := secureReplayFile(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return nil, errors.New("replay metadata changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > maxSize {
		return nil, errors.New("replay metadata size is invalid")
	}
	return data, nil
}

func writeReplayAnchor(path string, anchor replayAnchor) error {
	return writeReplayJSON(path, anchor, ".portforward-anchor-*", 4096)
}

func writeReplayEntries(path string, deviceID mesh.DeviceID, generation uint64, entries map[string]int64) error {
	return writeReplayJSON(path, replaySnapshot{
		Version: replayStoreVersion, DeviceID: string(deviceID), Generation: generation, Entries: entries,
	}, ".portforward-replay-*", maxReplayStoreSize)
}

func writeReplayJSON(path string, value any, pattern string, maxSize int64) error {
	dir := filepath.Dir(path)
	if err := secureReplayDirectory(dir); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || int64(len(data)) > maxSize {
		return errors.New("replay metadata exceeds size limit")
	}
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tempPath := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(tempPath)
	}
	if err := file.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if err := secureReplayFile(tempPath); err != nil {
		cleanup()
		return err
	}
	for len(data) > 0 {
		n, writeErr := file.Write(data)
		if writeErr != nil {
			cleanup()
			return writeErr
		}
		if n == 0 {
			cleanup()
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if err := replaceReplayFile(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}

func replayStoreNow(replay *FileReplay) time.Time {
	now := time.Now().UTC()
	if replay.Now != nil {
		now = replay.Now().UTC()
	}
	return now
}

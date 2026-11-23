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
	replayStoreVersion = 1
	maxReplayStoreSize = 16 << 20
	defaultReplayLimit = 100000
)

type replaySnapshot struct {
	Version  int               `json:"version"`
	DeviceID string            `json:"device_id"`
	Entries  map[string]int64  `json:"entries"`
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

	unlock, err := lockReplayFile(r.Path)
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

	entries, err := readReplayEntries(r.Path, r.DeviceID)
	if err != nil {
		return fmt.Errorf("%w: read replay store: %v", ErrReplayUnavailable, err)
	}
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
	entries[jti] = expiresAt.UTC().UnixMilli()
	if err := writeReplayEntries(r.Path, r.DeviceID, entries); err != nil {
		return fmt.Errorf("%w: persist replay consumption: %v", ErrReplayUnavailable, err)
	}
	return nil
}

func readReplayEntries(path string, deviceID mesh.DeviceID) (map[string]int64, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]int64), nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxReplayStoreSize {
		return nil, errors.New("replay store is not a bounded regular file")
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
		return nil, errors.New("replay store changed during open")
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReplayStoreSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxReplayStoreSize {
		return nil, errors.New("replay store size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot replaySnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("replay store contains trailing JSON")
		}
		return nil, err
	}
	if snapshot.Version != replayStoreVersion || snapshot.DeviceID != string(deviceID) || snapshot.Entries == nil || len(snapshot.Entries) > defaultReplayLimit {
		return nil, errors.New("replay store scope or version mismatch")
	}
	for jti, expiryMS := range snapshot.Entries {
		if !jtiPattern.MatchString(jti) || expiryMS <= 0 {
			return nil, errors.New("replay store contains invalid entry")
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(jti)
		if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != jti {
			return nil, errors.New("replay store contains invalid JTI")
		}
	}
	return snapshot.Entries, nil
}

func writeReplayEntries(path string, deviceID mesh.DeviceID, entries map[string]int64) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(replaySnapshot{
		Version: replayStoreVersion, DeviceID: string(deviceID), Entries: entries,
	})
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxReplayStoreSize {
		return errors.New("replay store exceeds size limit")
	}
	file, err := os.CreateTemp(dir, ".portforward-replay-*")
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

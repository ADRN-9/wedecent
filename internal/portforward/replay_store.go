package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	replayStoreVersion             = 2
	legacyReplayStoreVersion       = 1
	maxReplayStoreSize             = 16 << 20
	defaultReplayLimit             = 100000
	replayInitializationRetryLimit = 20
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

type replayInitialization struct {
	Version  int    `json:"version"`
	DeviceID string `json:"device_id"`
	Status   string `json:"status"`
	Legacy   bool   `json:"legacy,omitempty"`
}

// RejectExistingFileReplayState prevents a production remote-authority rollout
// from silently ignoring or migrating potentially consumed file-backed JTIs.
func RejectExistingFileReplayState(path string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return ErrReplayUnavailable
	}
	for _, suffix := range []string{"", ".init", ".lock", ".anchor", ".pending", ".lock.bootstrap"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			return fmt.Errorf("%w: existing local replay artifact %s requires explicit identity recovery", ErrReplayUnavailable, filepath.Base(path+suffix))
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: inspect local replay artifact: %v", ErrReplayUnavailable, err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: inspect local replay staging directory: %v", ErrReplayUnavailable, err)
	}
	prefix := replayStagingPrefix(path)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			return fmt.Errorf("%w: existing local replay staging artifact %s requires explicit identity recovery", ErrReplayUnavailable, entry.Name())
		}
	}
	return nil
}

// FileReplay provides cross-process, durable, device-scoped single-use JTI
// consumption for tests and explicitly local-only development. It does not
// resist same-account paired snapshot-and-anchor rollback.
type FileReplay struct {
	Path                 string
	DeviceID             mesh.DeviceID
	MaxEntries           int
	Now                  func() time.Time
	AllowLegacyMigration bool
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
	return NewPersistentAuthorizationVerifierWithLegacyMigration(path, localDeviceID, publicKey, false)
}

func NewPersistentAuthorizationVerifierWithLegacyMigration(path string, localDeviceID mesh.DeviceID, publicKey ed25519.PublicKey, allowLegacyMigration bool) (*AuthorizationVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrAuthorizationInvalid
	}
	replay, err := NewFileReplay(path, localDeviceID)
	if err != nil {
		return nil, err
	}
	replay.AllowLegacyMigration = allowLegacyMigration
	return &AuthorizationVerifier{
		PublicKey: append(ed25519.PublicKey(nil), publicKey...),
		Replay:    replay,
	}, nil
}

func (r *FileReplay) ConsumePortForwardAuthorization(ctx context.Context, jti string, expiresAt time.Time) (result error) {
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

	if err := ensureReplayInitializationContext(ctx, r.Path, r.DeviceID, r.AllowLegacyMigration); err != nil {
		return fmt.Errorf("%w: replay initialization: %v", ErrReplayUnavailable, err)
	}
	unlock, _, err := lockReplayFileContext(ctx, r.Path)
	if err != nil {
		return errors.Join(ErrReplayUnavailable, fmt.Errorf("lock replay store: %w", err))
	}
	defer func() {
		if unlockErr := unlock(); unlockErr != nil {
			result = errors.Join(result, fmt.Errorf("%w: release replay store lock: %v", ErrReplayUnavailable, unlockErr))
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cleanupReplayStaging(r.Path); err != nil {
		return errors.Join(ErrReplayUnavailable, fmt.Errorf("clean replay staging files: %w", err))
	}
	now = replayStoreNow(r)
	if !expiresAt.After(now) {
		return ErrAuthorizationExpired
	}
	if expiresAt.Sub(now) > MaxAuthorizationLifetime {
		return ErrAuthorizationInvalid
	}

	snapshot, err := loadReplaySnapshot(r.Path, r.DeviceID, r.AllowLegacyMigration)
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
	// The staged snapshot is durable before the anchor advances. Startup can
	// finish this exact transaction after any crash point without resetting
	// replay history or accepting a previous generation.
	if err := writeReplayPending(r.Path, r.DeviceID, nextGeneration, entries); err != nil {
		return fmt.Errorf("%w: stage replay consumption: %v", ErrReplayUnavailable, err)
	}
	anchor, err := readReplayAnchor(r.Path+".anchor", r.DeviceID)
	if err != nil {
		return fmt.Errorf("%w: read replay anchor before commit: %v", ErrReplayUnavailable, err)
	}
	if err := recoverReplayPending(r.Path, r.DeviceID, anchor, false); err != nil {
		return fmt.Errorf("%w: commit replay consumption: %v", ErrReplayUnavailable, err)
	}
	return nil
}

func ensureReplayInitialization(path string, deviceID mesh.DeviceID, allowLegacyMigration bool) error {
	return ensureReplayInitializationContext(context.Background(), path, deviceID, allowLegacyMigration)
}

func ensureReplayInitializationContext(ctx context.Context, path string, deviceID mesh.DeviceID, allowLegacyMigration bool) error {
	if ctx == nil {
		return ErrReplayUnavailable
	}
	return ensureReplayInitializationAttemptContext(ctx, path, deviceID, allowLegacyMigration, 0)
}

func ensureReplayInitializationAttempt(path string, deviceID mesh.DeviceID, allowLegacyMigration bool, attempt int) (result error) {
	return ensureReplayInitializationAttemptContext(context.Background(), path, deviceID, allowLegacyMigration, attempt)
}

func ensureReplayInitializationAttemptContext(ctx context.Context, path string, deviceID mesh.DeviceID, allowLegacyMigration bool, attempt int) (result error) {
	dir := filepath.Dir(path)
	if err := secureReplayDirectory(dir); err != nil {
		return err
	}
	initPath := path + ".init"
	unlockReplay, lockCreated, err := lockReplayFileContext(ctx, path)
	if err != nil {
		return fmt.Errorf("lock replay store initialization: %w", err)
	}
	locked := true
	defer func() {
		if locked {
			if unlockErr := unlockReplay(); unlockErr != nil {
				result = errors.Join(result, fmt.Errorf("release replay initialization lock: %w", unlockErr))
			}
		}
	}()
	if err := cleanupReplayStaging(path); err != nil {
		return fmt.Errorf("clean replay staging files: %w", err)
	}
	marker, err := readReplayInitializationLocked(initPath, deviceID)
	if err == nil {
		if lockCreated {
			return errors.New("replay lock was deleted after initialization")
		}
		lockExists, lockErr := replayPathExists(path + ".lock")
		if lockErr != nil {
			return lockErr
		}
		stateExists, stateErr := replayPathExists(path)
		if stateErr != nil {
			return stateErr
		}
		anchorExists, anchorErr := replayPathExists(path + ".anchor")
		if anchorErr != nil {
			return anchorErr
		}
		pendingExists, pendingErr := replayPathExists(path + ".pending")
		if pendingErr != nil {
			return pendingErr
		}
		if marker.Status == "ready" && !lockExists {
			return errors.New("replay lock was deleted after initialization")
		}
		if marker.Legacy && !lockExists {
			return errors.New("legacy replay lock is missing")
		}
		if marker.Status == "pending" && !lockExists && (stateExists || anchorExists || pendingExists) {
			return errors.New("replay lock is missing during pending initialization")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stateExists, err := replayPathExists(path)
	if err != nil {
		return err
	}
	anchorExists, err := replayPathExists(path + ".anchor")
	if err != nil {
		return err
	}
	lockExists, err := replayPathExists(path + ".lock")
	if err != nil {
		return err
	}
	pendingExists, err := replayPathExists(path + ".pending")
	if err != nil {
		return err
	}
	if anchorExists || pendingExists {
		return errors.New("replay initialization marker is missing for an anchored or pending store")
	}
	if !stateExists && lockExists && !lockCreated && attempt < replayInitializationRetryLimit {
		// Another process may have published the lock before it acquired it.
		// Release and retry so its first initialization can publish the marker.
		if unlockErr := unlockReplay(); unlockErr != nil {
			locked = false
			return fmt.Errorf("release replay initialization lock before retry: %w", unlockErr)
		}
		locked = false
		if err := waitReplayLockContext(ctx); err != nil {
			return err
		}
		return ensureReplayInitializationAttemptContext(ctx, path, deviceID, allowLegacyMigration, attempt+1)
	}
	if stateExists || (lockExists && !lockCreated) {
		if !allowLegacyMigration || !stateExists || !lockExists {
			return fmt.Errorf("unmarked replay state cannot be safely initialized or rolled forward (state=%t lock=%t lock_created=%t anchor=%t pending=%t)", stateExists, lockExists, lockCreated, anchorExists, pendingExists)
		}
		legacy, readErr := readReplaySnapshot(path, deviceID)
		if readErr != nil || legacy.Version != legacyReplayStoreVersion {
			return errors.New("unmarked replay state is not an explicitly permitted legacy store")
		}
		return createReplayInitialization(path, replayInitialization{
			Version: replayStoreVersion, DeviceID: string(deviceID), Status: "pending", Legacy: true,
		})
	}
	return createReplayInitialization(path, replayInitialization{
		Version: replayStoreVersion, DeviceID: string(deviceID), Status: "pending",
	})
}

func waitReplayLockContext(ctx context.Context) error {
	if ctx == nil {
		return ErrReplayUnavailable
	}
	timer := time.NewTimer(5 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func replayPathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func createReplayInitialization(path string, marker replayInitialization) error {
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, replayStagingPattern(path, "init"))
	if err != nil {
		return err
	}
	tempPath := file.Name()
	cleanup := func(primary error) error {
		return cleanupReplayTemp(primary, file, tempPath)
	}
	if err := file.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if err := setReplayFileOwner(tempPath); err != nil {
		return cleanup(fmt.Errorf("set initial replay marker owner: %w", err))
	}
	if err := secureReplayFile(tempPath); err != nil {
		return cleanup(err)
	}
	for len(data) > 0 {
		n, writeErr := file.Write(data)
		if writeErr != nil {
			return cleanup(writeErr)
		}
		if n == 0 {
			return cleanup(io.ErrShortWrite)
		}
		data = data[n:]
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		return cleanupReplayTemp(err, nil, tempPath)
	}
	if err := createReplayFileExclusive(tempPath, path+".init"); errors.Is(err, os.ErrExist) {
		if cleanupErr := removeReplayTemp(tempPath); cleanupErr != nil {
			return errors.Join(err, cleanupErr)
		}
		var existing replayInitialization
		for attempt := 0; attempt < 5; attempt++ {
			existing, err = readReplayInitializationLocked(path+".init", mesh.DeviceID(marker.DeviceID))
			if err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if err != nil {
			return err
		}
		if existing.Version != marker.Version || existing.DeviceID != marker.DeviceID {
			return errors.New("concurrent replay initialization has a different device scope")
		}
		return nil
	} else if err != nil {
		return cleanupReplayTemp(err, nil, tempPath)
	}
	return nil
}

// readReplayInitializationLocked requires the replay store's .lock to be held.
func readReplayInitializationLocked(path string, deviceID mesh.DeviceID) (replayInitialization, error) {
	data, err := readReplayJSON(path, 4096)
	if err != nil {
		return replayInitialization{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var marker replayInitialization
	if err := decoder.Decode(&marker); err != nil {
		return replayInitialization{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return replayInitialization{}, errors.New("replay initialization marker contains trailing JSON")
		}
		return replayInitialization{}, err
	}
	if marker.Version != replayStoreVersion || marker.DeviceID != string(deviceID) ||
		(marker.Status != "pending" && marker.Status != "ready") {
		return replayInitialization{}, errors.New("replay initialization marker scope or status mismatch")
	}
	return marker, nil
}

func writeReplayInitialization(path string, marker replayInitialization) error {
	if marker.Status != "pending" && marker.Status != "ready" {
		return errors.New("invalid replay initialization status")
	}
	return writeReplayJSON(path+".init", marker, replayStagingPattern(path, "init"), 4096)
}

func loadReplaySnapshot(path string, deviceID mesh.DeviceID, allowLegacyMigration bool) (replaySnapshot, error) {
	// The caller holds path+".lock", which also serializes initialization markers.
	marker, err := readReplayInitializationLocked(path+".init", deviceID)
	if err != nil {
		return replaySnapshot{}, err
	}
	if marker.Status == "ready" {
		anchor, err := readReplayAnchor(path+".anchor", deviceID)
		if err != nil {
			return replaySnapshot{}, errors.New("initialized replay anchor is missing or invalid")
		}
		if err := recoverReplayPending(path, deviceID, anchor, false); err != nil {
			return replaySnapshot{}, err
		}
		anchor, err = readReplayAnchor(path+".anchor", deviceID)
		if err != nil {
			return replaySnapshot{}, err
		}
		snapshot, err := readReplaySnapshot(path, deviceID)
		if err != nil || snapshot.Version != replayStoreVersion || snapshot.Generation != anchor.Generation {
			return replaySnapshot{}, errors.New("replay state does not match its durable generation anchor")
		}
		return snapshot, nil
	}

	pendingExists, err := replayPathExists(path + ".pending")
	if err != nil {
		return replaySnapshot{}, err
	}
	if pendingExists {
		anchor, anchorErr := readReplayAnchor(path+".anchor", deviceID)
		if anchorErr != nil && !errors.Is(anchorErr, os.ErrNotExist) {
			return replaySnapshot{}, anchorErr
		}
		if err := recoverReplayPending(path, deviceID, anchor, true); err != nil {
			return replaySnapshot{}, err
		}
	} else {
		stateExists, stateErr := replayPathExists(path)
		if stateErr != nil {
			return replaySnapshot{}, stateErr
		}
		anchorExists, anchorErr := replayPathExists(path + ".anchor")
		if anchorErr != nil {
			return replaySnapshot{}, anchorErr
		}
		if stateExists && anchorExists {
			anchor, err := readReplayAnchor(path+".anchor", deviceID)
			if err != nil {
				return replaySnapshot{}, err
			}
			snapshot, err := readReplaySnapshot(path, deviceID)
			if err != nil || snapshot.Version != replayStoreVersion || snapshot.Generation != anchor.Generation {
				return replaySnapshot{}, errors.New("pending replay state and anchor are inconsistent")
			}
		} else if !stateExists && !anchorExists && !marker.Legacy {
			empty := make(map[string]int64)
			if err := writeReplayPending(path, deviceID, 0, empty); err != nil {
				return replaySnapshot{}, err
			}
			if err := recoverReplayPending(path, deviceID, replayAnchor{}, true); err != nil {
				return replaySnapshot{}, err
			}
		} else if marker.Legacy && stateExists && !anchorExists && allowLegacyMigration {
			legacy, err := readReplaySnapshot(path, deviceID)
			if err != nil || legacy.Version != legacyReplayStoreVersion {
				return replaySnapshot{}, errors.New("legacy replay store changed during migration")
			}
			if err := writeReplayPending(path, deviceID, 0, legacy.Entries); err != nil {
				return replaySnapshot{}, err
			}
			if err := recoverReplayPending(path, deviceID, replayAnchor{}, true); err != nil {
				return replaySnapshot{}, err
			}
		} else {
			return replaySnapshot{}, errors.New("pending replay initialization cannot safely recover missing state")
		}
	}

	anchor, err := readReplayAnchor(path+".anchor", deviceID)
	if err != nil {
		return replaySnapshot{}, err
	}
	snapshot, err := readReplaySnapshot(path, deviceID)
	if err != nil || snapshot.Version != replayStoreVersion || snapshot.Generation != anchor.Generation {
		return replaySnapshot{}, errors.New("recovered replay state does not match its generation anchor")
	}
	marker.Status = "ready"
	marker.Legacy = false
	if err := writeReplayInitialization(path, marker); err != nil {
		return replaySnapshot{}, err
	}
	return snapshot, nil
}

func writeReplayPending(path string, deviceID mesh.DeviceID, generation uint64, entries map[string]int64) error {
	return writeReplayJSON(path+".pending", replaySnapshot{
		Version: replayStoreVersion, DeviceID: string(deviceID), Generation: generation, Entries: entries,
	}, replayStagingPattern(path, "pending"), maxReplayStoreSize)
}

func recoverReplayPending(path string, deviceID mesh.DeviceID, anchor replayAnchor, allowMissingAnchor bool) error {
	pendingPath := path + ".pending"
	pending, err := readReplaySnapshot(pendingPath, deviceID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || pending.Version != replayStoreVersion {
		return errors.New("pending replay transaction is malformed")
	}
	anchorExists, err := replayPathExists(path + ".anchor")
	if err != nil {
		return err
	}
	if !anchorExists && !allowMissingAnchor {
		return errors.New("initialized replay anchor is missing during transaction recovery")
	}
	if anchorExists {
		anchor, err = readReplayAnchor(path+".anchor", deviceID)
		if err != nil {
			return err
		}
		if pending.Generation < anchor.Generation || pending.Generation > anchor.Generation+1 {
			return errors.New("pending replay generation is outside the recoverable window")
		}
	} else if pending.Generation > 1 {
		return errors.New("pending replay generation cannot initialize a missing anchor")
	}

	state, stateErr := readReplaySnapshot(path, deviceID)
	stateExists := stateErr == nil
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return stateErr
	}
	if stateExists {
		if state.Version == replayStoreVersion {
			if state.Generation > pending.Generation || state.Generation+1 < pending.Generation {
				return errors.New("pending replay transaction would roll back state")
			}
		} else if state.Version != legacyReplayStoreVersion {
			return errors.New("pending replay state has an unsupported version")
		}
	}
	if !anchorExists || anchor.Generation < pending.Generation {
		if anchorExists && pending.Generation != anchor.Generation+1 {
			return errors.New("pending replay transaction skipped a generation")
		}
		if err := writeReplayAnchor(path+".anchor", replayAnchor{
			Version: replayStoreVersion, DeviceID: string(deviceID), Generation: pending.Generation,
		}); err != nil {
			return err
		}
	}
	if stateExists && state.Version == replayStoreVersion && state.Generation == pending.Generation {
		if err := os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncReplayDirectory(filepath.Dir(path))
	}
	return replaceReplayFile(pendingPath, path)
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
	return writeReplayJSON(path, anchor, replayStagingPattern(path, "anchor"), 4096)
}

func writeReplayEntries(path string, deviceID mesh.DeviceID, generation uint64, entries map[string]int64) error {
	return writeReplayJSON(path, replaySnapshot{
		Version: replayStoreVersion, DeviceID: string(deviceID), Generation: generation, Entries: entries,
	}, replayStagingPattern(path, "replay"), maxReplayStoreSize)
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
	cleanup := func(primary error) error {
		return cleanupReplayTemp(primary, file, tempPath)
	}
	if err := file.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if err := setReplayFileOwner(tempPath); err != nil {
		return cleanup(fmt.Errorf("set replay file owner: %w", err))
	}
	if err := secureReplayFile(tempPath); err != nil {
		return cleanup(err)
	}
	for len(data) > 0 {
		n, writeErr := file.Write(data)
		if writeErr != nil {
			return cleanup(writeErr)
		}
		if n == 0 {
			return cleanup(io.ErrShortWrite)
		}
		data = data[n:]
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		return cleanupReplayTemp(err, nil, tempPath)
	}
	if err := replaceReplayFile(tempPath, path); err != nil {
		return cleanupReplayTemp(err, nil, tempPath)
	}
	return nil
}

// replayStagingPrefix isolates temporary files belonging to one replay store.
func replayStagingPrefix(path string) string {
	digest := sha256.Sum256([]byte(filepath.Clean(path)))
	return ".portforward-" + hex.EncodeToString(digest[:16]) + "-"
}

func replayStagingPattern(path, kind string) string {
	return replayStagingPrefix(path) + kind + "-*"
}

func validReplayStagingSuffix(suffix string) bool {
	if len(suffix) == 0 || len(suffix) > 64 {
		return false
	}
	for _, char := range suffix {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9')) {
			return false
		}
	}
	return true
}

// cleanupReplayStaging must run while the replay store's cross-process lock is held.
// Only recognized, private, regular staging files for this exact store are removed.
// Durable path+".pending" recovery records and files belonging to other stores are untouched.
// Legacy unscoped temporary names are not swept because their store ownership is ambiguous.
func cleanupReplayStaging(path string) error {
	return cleanupReplayStagingWith(path, os.Remove)
}

func cleanupReplayStagingWith(path string, remove func(string) error) error {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read replay staging directory: %w", err)
	}
	prefix := replayStagingPrefix(path)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		kind, suffix, ok := strings.Cut(strings.TrimPrefix(name, prefix), "-")
		if !ok || !validReplayStagingSuffix(suffix) {
			return fmt.Errorf("unexpected replay staging filename %q", name)
		}
		switch kind {
		case "init", "anchor", "replay", "pending", "lock":
		default:
			return fmt.Errorf("unexpected replay staging kind %q", kind)
		}

		tempPath := filepath.Join(dir, name)
		info, err := os.Lstat(tempPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect replay staging file %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("replay staging entry %s is not a regular file", name)
		}
		if err := setReplayFileOwner(tempPath); err != nil {
			return fmt.Errorf("set replay staging file owner %s: %w", name, err)
		}
		if err := secureReplayFile(tempPath); err != nil {
			return fmt.Errorf("refuse insecure replay staging file %s: %w", name, err)
		}
		if err := removeReplayTempWith(tempPath, remove); err != nil {
			return err
		}
	}
	return nil
}

func removeReplayTemp(path string) error {
	return removeReplayTempWith(path, os.Remove)
}

func removeReplayTempWith(path string, remove func(string) error) error {
	if err := remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove replay staging file %s: %w", filepath.Base(path), err)
	}
	return nil
}

func cleanupReplayTemp(primary error, file *os.File, path string) error {
	return cleanupReplayTempWith(primary, file, path, os.Remove)
}

func cleanupReplayTempWith(primary error, file interface{ Close() error }, path string, remove func(string) error) error {
	var cleanupErr error
	if file != nil {
		if err := file.Close(); err != nil {
			cleanupErr = fmt.Errorf("close replay staging file %s: %w", filepath.Base(path), err)
		}
	}
	cleanupErr = errors.Join(cleanupErr, removeReplayTempWith(path, remove))
	return errors.Join(primary, cleanupErr)
}

func replayStoreNow(replay *FileReplay) time.Time {
	now := time.Now().UTC()
	if replay.Now != nil {
		now = replay.Now().UTC()
	}
	return now
}

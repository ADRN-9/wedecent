package meshstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

const (
	routeReplayStoreVersion = 1
	maxRouteReplayStoreSize = 1 << 20
	maxRouteReplayJTIBytes  = 256
)

var ErrRouteReplayStoreInvalid = errors.New(
	"meshstate: invalid route authorization replay store",
)

type replayDiskState struct {
	Version int              `json:"version"`
	Used    map[string]int64 `json:"used"`
}

// FileRouteAuthorizationReplay is a restart-safe implementation of
// mesh.RouteAuthorizationReplay.
//
// One live instance should own a given path. All routing listeners in one
// agent process should share that instance.
type FileRouteAuthorizationReplay struct {
	mu   sync.Mutex
	path string
	used map[string]int64
	now  func() time.Time
}

var _ mesh.RouteAuthorizationReplay = (*FileRouteAuthorizationReplay)(nil)

// OpenFileRouteAuthorizationReplay opens restart-safe JTI consumption state.
//
// Missing state is valid and begins empty. Existing state must be a bounded,
// regular, non-symlink JSON file.
func OpenFileRouteAuthorizationReplay(
	path string,
) (*FileRouteAuthorizationReplay, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf(
			"%w: empty path",
			ErrRouteReplayStoreInvalid,
		)
	}

	r := &FileRouteAuthorizationReplay{
		path: path,
		used: make(map[string]int64),
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf(
			"%w: state must not be a symbolic link",
			ErrRouteReplayStoreInvalid,
		)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"%w: state is not a regular file",
			ErrRouteReplayStoreInvalid,
		)
	}
	if info.Size() <= 0 ||
		info.Size() > maxRouteReplayStoreSize {
		return nil, fmt.Errorf(
			"%w: invalid state size",
			ErrRouteReplayStoreInvalid,
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf(
			"meshstate: secure replay-store permissions: %w",
			err,
		)
	}

	var state replayDiskState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf(
			"%w: parse state: %v",
			ErrRouteReplayStoreInvalid,
			err,
		)
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf(
				"%w: multiple JSON values",
				ErrRouteReplayStoreInvalid,
			)
		}
		return nil, fmt.Errorf(
			"%w: trailing state: %v",
			ErrRouteReplayStoreInvalid,
			err,
		)
	}

	if state.Version != routeReplayStoreVersion {
		return nil, fmt.Errorf(
			"%w: unsupported version %d",
			ErrRouteReplayStoreInvalid,
			state.Version,
		)
	}

	now := r.currentTime()
	for jti, expiryMS := range state.Used {
		if err := validateStoredJTI(jti, expiryMS); err != nil {
			return nil, err
		}
		if time.UnixMilli(expiryMS).After(now) {
			r.used[jti] = expiryMS
		}
	}

	return r, nil
}

// ConsumeRouteAuthorization atomically consumes jti.
//
// Success is returned only after the new state has been persisted. Therefore
// a successful authorization cannot become reusable merely because the agent
// process restarts.
func (r *FileRouteAuthorizationReplay) ConsumeRouteAuthorization(
	ctx context.Context,
	jti string,
	expiresAt time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil {
		return mesh.ErrRouteAuthorizationReplayMissing
	}
	if err := validateJTI(jti); err != nil {
		return err
	}

	expiryMS := expiresAt.UTC().UnixMilli()
	if expiryMS <= 0 {
		return mesh.ErrRouteAuthorizationInvalid
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	now := r.currentTime()
	next := make(map[string]int64, len(r.used)+1)

	for usedJTI, usedExpiryMS := range r.used {
		if time.UnixMilli(usedExpiryMS).After(now) {
			next[usedJTI] = usedExpiryMS
		}
	}

	if _, exists := next[jti]; exists {
		return mesh.ErrRouteAuthorizationReplay
	}

	next[jti] = expiryMS

	// Persistence precedes the in-memory commit. On any write failure, this
	// instance does not burn the JTI.
	if err := r.saveLocked(next); err != nil {
		return err
	}

	r.used = next
	return nil
}

func (r *FileRouteAuthorizationReplay) currentTime() time.Time {
	if r != nil && r.now != nil {
		return r.now().UTC()
	}
	return time.Now().UTC()
}

func validateJTI(jti string) error {
	if jti == "" ||
		strings.TrimSpace(jti) != jti ||
		len(jti) > maxRouteReplayJTIBytes {
		return mesh.ErrRouteAuthorizationInvalid
	}
	return nil
}

func validateStoredJTI(jti string, expiryMS int64) error {
	if err := validateJTI(jti); err != nil {
		return fmt.Errorf(
			"%w: invalid JTI",
			ErrRouteReplayStoreInvalid,
		)
	}
	if expiryMS <= 0 {
		return fmt.Errorf(
			"%w: invalid expiry",
			ErrRouteReplayStoreInvalid,
		)
	}
	return nil
}

func (r *FileRouteAuthorizationReplay) saveLocked(
	used map[string]int64,
) error {
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf(
			"meshstate: create replay-store directory: %w",
			err,
		)
	}

	state := replayDiskState{
		Version: routeReplayStoreVersion,
		Used:    used,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if len(data) == 0 ||
		len(data) > maxRouteReplayStoreSize {
		return fmt.Errorf(
			"%w: invalid encoded size",
			ErrRouteReplayStoreInvalid,
		)
	}

	tmp, err := os.CreateTemp(dir, ".route-replay-*")
	if err != nil {
		return err
	}

	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := replaceReplayFile(tmpPath, r.path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return os.Chmod(r.path, 0o600)
}

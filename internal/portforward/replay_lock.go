package portforward

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"
)

type replayProcessLock struct {
	mu   sync.Mutex
	refs int
}

var replayProcessLocks = struct {
	sync.Mutex
	byPath map[string]*replayProcessLock
}{byPath: make(map[string]*replayProcessLock)}

func lockReplayProcessPathContext(ctx context.Context, path string, onWait func()) (func(), error) {
	if ctx == nil {
		return nil, errors.New("replay lock context is nil")
	}
	key := filepath.Clean(path)
	replayProcessLocks.Lock()
	lock := replayProcessLocks.byPath[key]
	if lock == nil {
		lock = &replayProcessLock{}
		replayProcessLocks.byPath[key] = lock
	}
	lock.refs++
	replayProcessLocks.Unlock()

	releaseRef := func() {
		replayProcessLocks.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(replayProcessLocks.byPath, key)
		}
		replayProcessLocks.Unlock()
	}
	for !lock.mu.TryLock() {
		if onWait != nil {
			onWait()
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			releaseRef()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return func() {
		lock.mu.Unlock()
		releaseRef()
	}, nil
}

// lockReplayProcessPath preserves the background-context helper for callers
// that do not own a cancellable operation.
func lockReplayProcessPath(path string) func() {
	unlock, err := lockReplayProcessPathContext(context.Background(), path, nil)
	if err != nil {
		panic(err)
	}
	return unlock
}

// lockReplayFile combines an in-process path lock with the platform file lock.
func lockReplayFile(path string) (func() error, bool, error) {
	return lockReplayFileContext(context.Background(), path)
}

func lockReplayFileContext(ctx context.Context, path string) (func() error, bool, error) {
	return lockReplayFileContextObserved(ctx, path, nil)
}

func lockReplayFileContextObserved(ctx context.Context, path string, onWait func()) (func() error, bool, error) {
	return lockReplayFileContextForObserved(ctx, path, path, onWait)
}

func lockReplayFileContextForObserved(ctx context.Context, path, statePath string, onWait func()) (func() error, bool, error) {
	unlockProcess, err := lockReplayProcessPathContext(ctx, path, onWait)
	if err != nil {
		return nil, false, err
	}
	unlockFile, created, err := lockReplayFileOSContext(ctx, path, statePath, onWait)
	if err != nil {
		unlockProcess()
		return nil, false, err
	}
	return func() error {
		return releaseReplayFileLock(unlockFile, unlockProcess)
	}, created, nil
}

func releaseReplayFileLock(unlockFile func() error, unlockProcess func()) error {
	err := unlockFile()
	unlockProcess()
	return err
}

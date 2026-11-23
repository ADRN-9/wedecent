package portforward

import (
	"path/filepath"
	"sync"
)

type replayProcessLock struct {
	mu   sync.Mutex
	refs int
}

var replayProcessLocks = struct {
	sync.Mutex
	byPath map[string]*replayProcessLock
}{byPath: make(map[string]*replayProcessLock)}

func lockReplayProcessPath(path string) func() {
	key := filepath.Clean(path)
	replayProcessLocks.Lock()
	lock := replayProcessLocks.byPath[key]
	if lock == nil {
		lock = &replayProcessLock{}
		replayProcessLocks.byPath[key] = lock
	}
	lock.refs++
	replayProcessLocks.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		replayProcessLocks.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(replayProcessLocks.byPath, key)
		}
		replayProcessLocks.Unlock()
	}
}

// lockReplayFile combines an in-process path lock with the platform file lock.
func lockReplayFile(path string) (func() error, bool, error) {
	unlockProcess := lockReplayProcessPath(path)
	unlockFile, created, err := lockReplayFileOS(path)
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

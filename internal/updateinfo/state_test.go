package updateinfo

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStateStoreMissingAndAdvance(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "client")
	path := StatePath(dir)
	store := NewStateStore(path)

	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != UpdateStateVersion || state.StableSequence != 0 {
		t.Fatalf("initial state = %#v", state)
	}

	if err := store.Advance(41); err != nil {
		t.Fatal(err)
	}
	state, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != 41 {
		t.Fatalf("sequence = %d, want 41", state.StableSequence)
	}

	// A second write exercises replacement of an existing state file. On
	// Windows this reaches the MoveFileExW replace+write-through path.
	if err := store.Advance(42); err != nil {
		t.Fatal(err)
	}
	state, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != 42 {
		t.Fatalf("sequence = %d, want 42", state.StableSequence)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "{\"version\":1,\"stable_sequence\":42}\n"; got != want {
		t.Fatalf("state file = %q, want %q", got, want)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".update-state-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary state files remain: %#v", matches)
	}
}

func TestStateStoreRejectsRollbackWithoutChangingState(t *testing.T) {
	path := StatePath(filepath.Join(t.TempDir(), "client"))
	store := NewStateStore(path)
	if err := store.Advance(42); err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []uint64{42, 41} {
		if err := store.Advance(sequence); !errors.Is(err, ErrRollback) {
			t.Fatalf("Advance(%d) error = %v, want ErrRollback", sequence, err)
		}
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != 42 {
		t.Fatalf("rollback attempt changed sequence to %d", state.StableSequence)
	}
	if err := store.Advance(0); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Advance(0) error = %v, want ErrInvalidState", err)
	}
}

func TestStateStoreRejectsInvalidPersistedForms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, UpdateStateFilename)
	tests := map[string]string{
		"zero sequence":   "{\"version\":1,\"stable_sequence\":0}\n",
		"wrong version":   "{\"version\":2,\"stable_sequence\":1}\n",
		"unknown field":   "{\"version\":1,\"stable_sequence\":1,\"extra\":true}\n",
		"reordered":       "{\"stable_sequence\":1,\"version\":1}\n",
		"pretty":          "{\n  \"version\": 1,\n  \"stable_sequence\": 1\n}\n",
		"multiple values": "{\"version\":1,\"stable_sequence\":1}\n{}\n",
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewStateStore(path).Load(); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("Load() error = %v, want ErrInvalidState", err)
			}
		})
	}
}

func TestStateStoreRejectsOversizedAndNonRegularState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, UpdateStateFilename)
	if err := os.WriteFile(path, []byte(strings.Repeat("x", MaxUpdateStateBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStateStore(path).Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("oversized Load() error = %v, want ErrInvalidState", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStateStore(path).Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("directory Load() error = %v, want ErrInvalidState", err)
	}
}

func TestStateStoreRejectsSymlinkStateAndDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	realState := filepath.Join(target, "real.json")
	if err := os.WriteFile(realState, []byte("{\"version\":1,\"stable_sequence\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state-link.json")
	if err := os.Symlink(realState, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := NewStateStore(link).Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("symlink Load() error = %v, want ErrInvalidState", err)
	}

	dirLink := filepath.Join(root, "dir-link")
	if err := os.Symlink(target, dirLink); err != nil {
		t.Skipf("directory symlink creation unavailable: %v", err)
	}
	if err := NewStateStore(filepath.Join(dirLink, UpdateStateFilename)).Advance(2); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("symlink-directory Advance() error = %v, want ErrInvalidState", err)
	}
}

func TestStateStoreRejectsBroadUnixPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, UpdateStateFilename)
	if err := os.WriteFile(path, []byte("{\"version\":1,\"stable_sequence\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStateStore(path).Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("broad-permission Load() error = %v, want ErrInvalidState", err)
	}
}

func TestStateStoreRequiresPath(t *testing.T) {
	var nilStore *StateStore
	if _, err := nilStore.Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("nil Load() error = %v, want ErrInvalidState", err)
	}
	if err := nilStore.Advance(1); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("nil Advance() error = %v, want ErrInvalidState", err)
	}
	store := NewStateStore("")
	if _, err := store.Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("empty-path Load() error = %v, want ErrInvalidState", err)
	}
}

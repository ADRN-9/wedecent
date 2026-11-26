package updateinfo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
		"zero sequence":     "{\"version\":1,\"stable_sequence\":0}\n",
		"wrong version":     "{\"version\":2,\"stable_sequence\":1}\n",
		"unknown field":     "{\"version\":1,\"stable_sequence\":1,\"extra\":true}\n",
		"reordered":         "{\"stable_sequence\":1,\"version\":1}\n",
		"pretty":            "{\n  \"version\": 1,\n  \"stable_sequence\": 1\n}\n",
		"multiple values":   "{\"version\":1,\"stable_sequence\":1}\n{}\n",
		"v2 missing keyset": "{\"version\":2,\"stable_sequence\":1}\n",
		"v2 invalid digest": "{\"version\":2,\"stable_sequence\":0,\"keyset_epoch\":1,\"keyset_digest\":\"bad\"}\n",
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

func TestStateStorePersistsVerifiedKeysetAndSequenceAtomically(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, keyset := keysetFixture(t, now)
	body, signature := signKeyset(t, keyset, rootPrivate, now)

	path := StatePath(filepath.Join(t.TempDir(), "client"))
	store := NewStateStore(path)
	if err := store.Advance(41); err != nil {
		t.Fatal(err)
	}
	verified, err := store.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, body, signature, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Epoch() != keyset.Epoch {
		t.Fatalf("verified keyset epoch = %d, want %d", verified.Epoch(), keyset.Epoch)
	}
	if _, err := store.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, body, signature, now); err != nil {
		t.Fatalf("idempotent keyset verification failed: %v", err)
	}

	lower := keyset
	lower.Epoch--
	lowerBody, lowerSignature := signKeyset(t, lower, rootPrivate, now)
	if _, err := store.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, lowerBody, lowerSignature, now); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("lower keyset epoch error = %v, want ErrKeysetRollback", err)
	}

	equivocation := keyset
	equivocation.ExpiresAt = now.Add(23 * time.Hour).UTC().Format(time.RFC3339)
	equivocationBody, equivocationSignature := signKeyset(t, equivocation, rootPrivate, now)
	if _, err := store.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, equivocationBody, equivocationSignature, now); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("same-epoch equivocation error = %v, want ErrKeysetRollback", err)
	}

	next := keyset
	next.Epoch++
	nextBody, nextSignature := signKeyset(t, next, rootPrivate, now)
	rotated, err := store.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, nextBody, nextSignature, now)
	if err != nil {
		t.Fatalf("monotonic keyset rotation failed: %v", err)
	}
	if rotated.Epoch() != next.Epoch {
		t.Fatalf("rotated keyset epoch = %d, want %d", rotated.Epoch(), next.Epoch)
	}
	if err := store.Advance(42); err != nil {
		t.Fatal(err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != UpdateStateVersionWithKeyset || state.StableSequence != 42 ||
		state.KeysetEpoch != next.Epoch || state.KeysetDigest != rotated.Digest() {
		t.Fatalf("persisted update state = %#v", state)
	}
}

func TestStateStoreKeysetStateCanPrecedeFirstUpdate(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, keyset := keysetFixture(t, now)
	body, signature := signKeyset(t, keyset, rootPrivate, now)
	store := NewStateStore(StatePath(filepath.Join(t.TempDir(), "client")))
	verified, err := store.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, body, signature, now)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != 0 || state.KeysetEpoch != keyset.Epoch || state.KeysetDigest != verified.Digest() {
		t.Fatalf("initial keyset state = %#v", state)
	}
	if err := store.Advance(1); err != nil {
		t.Fatal(err)
	}
	state, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != 1 || state.KeysetEpoch != keyset.Epoch || state.KeysetDigest != verified.Digest() {
		t.Fatalf("sequence advancement lost keyset state: %#v", state)
	}
}

func TestStateStoreRejectsInvalidKeysetVerification(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	store := NewStateStore(StatePath(filepath.Join(t.TempDir(), "client")))
	if _, err := store.VerifyAndAdvanceKeyset(context.Background(), "root-1", nil, []byte("{}"), []byte("invalid"), now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("invalid keyset verification error = %v, want ErrInvalidKeyset", err)
	}
}


func TestStateStoreKeysetAntiRollbackSurvivesRestartAndRejectsCorruption(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, keyset := keysetFixture(t, now)
	body, signature := signKeyset(t, keyset, rootPrivate, now)

	path := StatePath(filepath.Join(t.TempDir(), "client"))
	first := NewStateStore(path)
	verified, err := first.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, body, signature, now)
	if err != nil {
		t.Fatal(err)
	}

	// A new store models a fresh process reopening the protected state.
	restarted := NewStateStore(path)
	state, err := restarted.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != UpdateStateVersionWithKeyset ||
		state.KeysetEpoch != keyset.Epoch || state.KeysetDigest != verified.Digest() {
		t.Fatalf("reopened keyset state = %#v", state)
	}

	lower := keyset
	lower.Epoch--
	lowerBody, lowerSignature := signKeyset(t, lower, rootPrivate, now)
	if _, err := restarted.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, lowerBody, lowerSignature, now); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("restarted lower-epoch verification error = %v, want ErrKeysetRollback", err)
	}

	equivocation := keyset
	equivocation.ExpiresAt = now.Add(23 * time.Hour).UTC().Format(time.RFC3339)
	equivocationBody, equivocationSignature := signKeyset(t, equivocation, rootPrivate, now)
	if _, err := restarted.VerifyAndAdvanceKeyset(context.Background(), keyset.RootKeyID, rootPublic, equivocationBody, equivocationSignature, now); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("restarted same-epoch equivocation error = %v, want ErrKeysetRollback", err)
	}

	if err := os.WriteFile(path, []byte(`{"version":2,"stable_sequence":0,"keyset_epoch":7,"keyset_digest":"broken"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStateStore(path).Load(); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("corrupt persisted keyset state error = %v, want ErrInvalidState", err)
	}
}

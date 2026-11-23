package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestAuthorizationIssuerCreatesBoundedSingleUseCapability(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.JTI = ""
	claims.IssuedAtUnixMS = 0
	claims.ExpiresAtUnixMS = 0
	claims.Route.ExpiresAt = time.Time{}
	issuer := AuthorizationIssuer{
		Signer:   privateKey,
		Lifetime: 30 * time.Second,
		Now:      func() time.Time { return now },
		Random:   bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)),
	}
	auth, err := issuer.Issue(context.Background(), claims)
	if err != nil {
		t.Fatal(err)
	}
	if len(auth.Claims.JTI) != 22 || auth.Claims.ExpiresAtUnixMS-auth.Claims.IssuedAtUnixMS != int64((30*time.Second)/time.Millisecond) {
		t.Fatalf("issuer produced invalid JTI or lifetime: %#v", auth.Claims)
	}
	if !auth.Claims.Route.ExpiresAt.Equal(time.UnixMilli(auth.Claims.ExpiresAtUnixMS).UTC()) {
		t.Fatal("route expiry was not bound to authorization expiry")
	}
	replay := NewMemoryReplay(4)
	replay.Now = func() time.Time { return now }
	verifier := AuthorizationVerifier{PublicKey: publicKey, Replay: replay, Now: func() time.Time { return now }}
	if _, err := verifier.VerifyAndConsume(context.Background(), auth); err != nil {
		t.Fatalf("issued capability did not verify: %v", err)
	}
	if _, err := verifier.VerifyAndConsume(context.Background(), auth); !errors.Is(err, ErrAuthorizationReplay) {
		t.Fatalf("issued capability replay error = %v", err)
	}
}

func TestAuthorizationIssuerRejectsInvalidLifetimeAndCallerOwnedReplayFields(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.JTI = ""
	claims.IssuedAtUnixMS = 0
	claims.ExpiresAtUnixMS = 0
	claims.Route.ExpiresAt = time.Time{}
	if _, err := (AuthorizationIssuer{Signer: privateKey, Lifetime: MaxAuthorizationLifetime + time.Second}).Issue(context.Background(), claims); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("overlong lifetime error = %v", err)
	}
	claims.JTI = testClaims(now, DirectionLocal).JTI
	if _, err := (AuthorizationIssuer{Signer: privateKey}).Issue(context.Background(), claims); !errors.Is(err, ErrAuthorizationInvalid) {
		t.Fatalf("caller-supplied JTI error = %v", err)
	}
}

func TestFileReplayPersistsAcrossProcessRestart(t *testing.T) {
	path := newReplayTestPath(t)
	expiry := time.Now().UTC().Add(time.Minute).UnixMilli()
	run := func(expectReplay bool) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestFileReplayProcessHelper$")
		cmd.Env = append(os.Environ(),
			"WEDECENT_REPLAY_HELPER_PATH="+path,
			"WEDECENT_REPLAY_HELPER_EXPIRY="+strconv.FormatInt(expiry, 10),
			"WEDECENT_REPLAY_HELPER_EXPECT_REPLAY="+strconv.FormatBool(expectReplay),
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("replay helper failed (expectReplay=%v): %v\n%s", expectReplay, err, output)
		}
	}
	run(false)
	run(true)
}

func TestFileReplayProcessHelper(t *testing.T) {
	path := os.Getenv("WEDECENT_REPLAY_HELPER_PATH")
	if path == "" {
		return
	}
	expiry, err := strconv.ParseInt(os.Getenv("WEDECENT_REPLAY_HELPER_EXPIRY"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	expectReplay, err := strconv.ParseBool(os.Getenv("WEDECENT_REPLAY_HELPER_EXPECT_REPLAY"))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	err = replay.ConsumePortForwardAuthorization(
		context.Background(),
		base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
		time.UnixMilli(expiry),
	)
	if expectReplay {
		if !errors.Is(err, ErrAuthorizationReplay) {
			t.Fatalf("consume error = %v, want replay", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
}

func TestFileReplayInitialMarkerAndLockHavePrivateOwnership(t *testing.T) {
	dir := newReplayTestDir(t)
	path := filepath.Join(dir, "replay.json")
	if err := ensureReplayInitialization(path, testInitiator, false); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path + ".init", path + ".init.lock"} {
		if err := secureReplayFile(file); err != nil {
			t.Fatalf("initial replay metadata %s is not private: %v", filepath.Base(file), err)
		}
	}
}

func TestFileReplayConsumptionIsAtomicAcrossInstances(t *testing.T) {
	path := newReplayTestPath(t)
	jti := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	expiry := time.Now().UTC().Add(time.Minute)
	const workers = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes, replays := 0, 0
	failures := make([]error, 0)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replay, err := NewFileReplay(path, testInitiator)
			if err == nil {
				err = replay.ConsumePortForwardAuthorization(context.Background(), jti, expiry)
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrAuthorizationReplay):
				replays++
			default:
				failures = append(failures, err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 || replays != workers-1 || len(failures) != 0 {
		t.Fatalf("successes=%d replays=%d failures=%v", successes, replays, failures)
	}
}

func TestFileReplayConcurrentInitializationIsSerialized(t *testing.T) {
	path := newReplayTestPath(t)
	const workers = 24
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	failures := make([]error, 0)
	expiry := time.Now().UTC().Add(time.Minute)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			replay, err := NewFileReplay(path, testInitiator)
			if err == nil {
				raw := make([]byte, 16)
				raw[0], raw[1] = byte(index), byte(index>>8)
				jti := base64.RawURLEncoding.EncodeToString(raw)
				err = replay.ConsumePortForwardAuthorization(context.Background(), jti, expiry)
			}
			if err != nil {
				mu.Lock()
				failures = append(failures, err)
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if len(failures) != 0 {
		t.Fatalf("concurrent replay initialization/consumption failures: %v", failures)
	}
}

func TestFileReplayPrunesExpiredEntriesAndRejectsExpiredConsumption(t *testing.T) {
	path := newReplayTestPath(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	replay.MaxEntries = 1
	replay.Now = func() time.Time { return now }
	oldJTI := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	newJTI := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), oldJTI, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	replay.Now = func() time.Time { return now.Add(2 * time.Second) }
	if err := replay.ConsumePortForwardAuthorization(context.Background(), newJTI, now.Add(time.Minute)); err != nil {
		t.Fatalf("expired entry was not pruned: %v", err)
	}
	if err := replay.ConsumePortForwardAuthorization(context.Background(), oldJTI, now.Add(time.Second)); !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("expired capability error = %v", err)
	}
}

func TestFileReplayRejectsDeletedStateAfterInitialization(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	firstJTI := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	secondJTI := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	expiry := time.Now().UTC().Add(time.Minute)
	if err := replay.ConsumePortForwardAuthorization(context.Background(), firstJTI, expiry); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := replay.ConsumePortForwardAuthorization(context.Background(), secondJTI, expiry); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("deleted replay state error = %v, want fail-closed unavailable", err)
	}
}

func TestFileReplayRejectsDeletedStateAndLockTogether(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	nextJTI := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), nextJTI, time.Now().UTC().Add(time.Minute)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("deleted state and lock error = %v, want fail-closed replay unavailable", err)
	}
}

func TestFileReplayRejectsDeletedLockAfterInitialization(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	nextJTI := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), nextJTI, time.Now().UTC().Add(time.Minute)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("deleted lock error = %v, want fail-closed replay unavailable", err)
	}
}

func TestFileReplayRejectsDeletedGenerationAnchor(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	firstJTI := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	secondJTI := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	expiry := time.Now().UTC().Add(time.Minute)
	if err := replay.ConsumePortForwardAuthorization(context.Background(), firstJTI, expiry); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".anchor"); err != nil {
		t.Fatal(err)
	}
	if err := replay.ConsumePortForwardAuthorization(context.Background(), secondJTI, expiry); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("deleted generation anchor error = %v, want fail-closed replay unavailable", err)
	}
}

func TestFileReplayMigratesLegacyUnanchoredStateOnce(t *testing.T) {
	dir := newReplayTestDir(t)
	path := filepath.Join(dir, "portforward-replay.json")
	if err := secureReplayDirectory(dir); err != nil {
		t.Fatal(err)
	}
	legacyJTI := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	nextJTI := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	expiry := time.Now().UTC().Add(time.Minute)
	if err := writeReplayJSON(path, replaySnapshot{
		Version:  legacyReplayStoreVersion,
		DeviceID: string(testInitiator),
		Entries:  map[string]int64{legacyJTI: expiry.UnixMilli()},
	}, ".legacy-replay-*", maxReplayStoreSize); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := setReplayFileOwner(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := secureReplayFile(path + ".lock"); err != nil {
		t.Fatalf("legacy replay lock is not private: %v", err)
	}
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	replay.AllowLegacyMigration = true
	if err := replay.ConsumePortForwardAuthorization(context.Background(), legacyJTI, expiry); !errors.Is(err, ErrAuthorizationReplay) {
		t.Fatalf("legacy replay entry was not retained during migration: %v", err)
	}
	if err := replay.ConsumePortForwardAuthorization(context.Background(), nextJTI, expiry); err != nil {
		t.Fatalf("legacy replay state migration failed: %v", err)
	}
	snapshot, err := readReplaySnapshot(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != replayStoreVersion || snapshot.Generation != 1 {
		t.Fatalf("migrated replay state = version %d generation %d", snapshot.Version, snapshot.Generation)
	}
	if _, ok := snapshot.Entries[legacyJTI]; !ok {
		t.Fatal("legacy replay entries were lost during migration")
	}
}
func TestFileReplayRejectsOlderStateGeneration(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	firstJTI := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	secondJTI := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	thirdJTI := base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa"))
	expiry := time.Now().UTC().Add(time.Minute)
	if err := replay.ConsumePortForwardAuthorization(context.Background(), firstJTI, expiry); err != nil {
		t.Fatal(err)
	}
	olderState, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := replay.ConsumePortForwardAuthorization(context.Background(), secondJTI, expiry); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, olderState, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replay.ConsumePortForwardAuthorization(context.Background(), thirdJTI, expiry); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("replayed older state error = %v, want generation mismatch", err)
	}
}

func TestFileReplayStorageUsesPrivateDirectoryAndFilePermissions(t *testing.T) {
	dir := newReplayTestDir(t)
	path := filepath.Join(dir, "replay.json")
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := secureReplayDirectory(dir); err != nil {
		t.Fatalf("verify replay directory security: %v", err)
	}
	for _, file := range []string{path, path + ".lock", path + ".anchor", path + ".init", path + ".init.lock"} {
		if err := secureReplayFile(file); err != nil {
			t.Fatalf("verify replay file %s: %v", filepath.Base(file), err)
		}
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(dir); err != nil {
			t.Fatal(err)
		} else if info.Mode().Perm() != 0o700 {
			t.Fatalf("replay directory permissions = %o, want 700", info.Mode().Perm())
		}
		for _, file := range []string{path, path + ".lock", path + ".anchor", path + ".init", path + ".init.lock"} {
			info, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("%s permissions = %o, want 600", filepath.Base(file), info.Mode().Perm())
			}
		}
	}
}

func TestFileReplayRejectsWrongDeviceScopeAndCorruptState(t *testing.T) {
	path := newReplayTestPath(t)
	first, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	if err := first.ConsumePortForwardAuthorization(context.Background(), jti, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	other, err := NewFileReplay(path, testDestination)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.ConsumePortForwardAuthorization(context.Background(), base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210")), time.Now().UTC().Add(time.Minute)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("wrong device scope error = %v", err)
	}
	if err := os.WriteFile(path, []byte("{malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.ConsumePortForwardAuthorization(context.Background(), base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa")), time.Now().UTC().Add(time.Minute)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("corrupt state error = %v", err)
	}
}

func TestFileReplayRecoversPendingCommitAcrossCrashBoundaries(t *testing.T) {
	stages := []struct {
		name          string
		advanceAnchor bool
		publishState  bool
	}{
		{name: "pending_written"},
		{name: "anchor_written", advanceAnchor: true},
		{name: "snapshot_published", advanceAnchor: true, publishState: true},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			path := newReplayTestPath(t)
			initial, err := NewFileReplay(path, testInitiator)
			if err != nil {
				t.Fatal(err)
			}
			initialJTI := base64.RawURLEncoding.EncodeToString([]byte("cccccccccccccccc"))
			initialExpiry := time.Now().UTC().Add(time.Minute)
			if err := initial.ConsumePortForwardAuthorization(context.Background(), initialJTI, initialExpiry); err != nil {
				t.Fatalf("initialize replay snapshot: %v", err)
			}
			current, err := readReplaySnapshot(path, testInitiator)
			if err != nil {
				t.Fatal(err)
			}
			entries := make(map[string]int64, len(current.Entries)+1)
			for jti, expiry := range current.Entries {
				entries[jti] = expiry
			}
			pendingJTI := base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa"))
			nextJTI := base64.RawURLEncoding.EncodeToString([]byte("bbbbbbbbbbbbbbbb"))
			expiry := time.Now().UTC().Add(time.Minute)
			entries[pendingJTI] = expiry.UnixMilli()
			generation := current.Generation + 1
			if err := writeReplayPending(path, testInitiator, generation, entries); err != nil {
				t.Fatal(err)
			}
			if stage.advanceAnchor {
				if err := writeReplayAnchor(path+".anchor", replayAnchor{
					Version: replayStoreVersion, DeviceID: string(testInitiator), Generation: generation,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if stage.publishState {
				if err := writeReplayEntries(path, testInitiator, generation, entries); err != nil {
					t.Fatal(err)
				}
			}

			recovered, err := NewFileReplay(path, testInitiator)
			if err != nil {
				t.Fatalf("recover after simulated crash: %v", err)
			}
			if err := recovered.ConsumePortForwardAuthorization(context.Background(), pendingJTI, expiry); !errors.Is(err, ErrAuthorizationReplay) {
				t.Fatalf("pending authorization after recovery = %v, want replay", err)
			}
			if err := recovered.ConsumePortForwardAuthorization(context.Background(), nextJTI, expiry); err != nil {
				t.Fatalf("new authorization after recovery: %v", err)
			}
			snapshot, err := readReplaySnapshot(path, testInitiator)
			if err != nil {
				t.Fatal(err)
			}
			anchor, err := readReplayAnchor(path+".anchor", testInitiator)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Generation != anchor.Generation || snapshot.Generation != generation+1 {
				t.Fatalf("recovered state generation=%d anchor=%d, want %d", snapshot.Generation, anchor.Generation, generation+1)
			}
			if _, ok := snapshot.Entries[pendingJTI]; !ok {
				t.Fatal("recovery lost the pending replay entry")
			}
			if _, err := os.Stat(path + ".pending"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("pending transaction remains after recovery: %v", err)
			}
		})
	}
}

func newReplayTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "replay-state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create private replay test directory: %v", err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatalf("set private replay test directory owner: %v", err)
	}
	return dir
}

func newReplayTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(newReplayTestDir(t), "portforward-replay.json")
}

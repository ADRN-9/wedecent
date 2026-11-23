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
	for _, file := range []string{path + ".init", path + ".lock"} {
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

func TestFileReplayConcurrentInitializationAcrossProcesses(t *testing.T) {
	const rounds = 3
	const workers = 8

	type childProcess struct {
		cmd    *exec.Cmd
		output bytes.Buffer
	}
	children := make([]*childProcess, 0, rounds*workers)
	defer func() {
		for _, child := range children {
			if child.cmd.ProcessState == nil {
				_ = child.cmd.Process.Kill()
				_ = child.cmd.Wait()
			}
		}
	}()

	for round := 0; round < rounds; round++ {
		path := newReplayTestPath(t)
		barrier := path + ".start"
		expiry := time.Now().UTC().Add(time.Minute).UnixMilli()
		roundChildren := make([]*childProcess, 0, workers)
		jtis := make([]string, 0, workers)

		for i := 0; i < workers; i++ {
			raw := make([]byte, 16)
			raw[0], raw[1] = byte(round+1), byte(i+1)
			jti := base64.RawURLEncoding.EncodeToString(raw)
			jtis = append(jtis, jti)
			cmd := exec.Command(os.Args[0], "-test.run=^TestFileReplayConcurrentProcessHelper$")
			cmd.Env = append(os.Environ(),
				"WEDECENT_REPLAY_PROCESS_PATH="+path,
				"WEDECENT_REPLAY_PROCESS_BARRIER="+barrier,
				"WEDECENT_REPLAY_PROCESS_EXPIRY="+strconv.FormatInt(expiry, 10),
				"WEDECENT_REPLAY_PROCESS_JTI="+jti,
			)
			child := &childProcess{cmd: cmd}
			cmd.Stdout, cmd.Stderr = &child.output, &child.output
			if err := cmd.Start(); err != nil {
				t.Fatalf("start replay process round %d worker %d: %v", round, i, err)
			}
			children = append(children, child)
			roundChildren = append(roundChildren, child)
		}

		if err := os.WriteFile(barrier, []byte("start"), 0o600); err != nil {
			t.Fatal(err)
		}
		for i, child := range roundChildren {
			if err := child.cmd.Wait(); err != nil {
				t.Errorf("replay process round %d worker %d failed: %v\n%s", round, i, err, child.output.String())
			}
		}

		snapshot, err := readReplaySnapshot(path, testInitiator)
		if err != nil {
			t.Fatalf("read replay snapshot after process round %d: %v", round, err)
		}
		anchor, err := readReplayAnchor(path+".anchor", testInitiator)
		if err != nil {
			t.Fatalf("read replay anchor after process round %d: %v", round, err)
		}
		if len(snapshot.Entries) != workers || snapshot.Generation != workers || anchor.Generation != workers {
			t.Fatalf("round %d lost concurrent replay updates: entries=%d snapshot_generation=%d anchor_generation=%d, want %d",
				round, len(snapshot.Entries), snapshot.Generation, anchor.Generation, workers)
		}
		for _, jti := range jtis {
			if _, ok := snapshot.Entries[jti]; !ok {
				t.Errorf("round %d lost successful process replay entry %s", round, jti)
			}
		}
		marker, err := readReplayInitializationLocked(path+".init", testInitiator)
		if err != nil || marker.Status != "ready" {
			t.Errorf("round %d initialization marker = %#v, error = %v; want ready", round, marker, err)
		}
		if _, err := os.Lstat(path + ".pending"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("round %d retained pending transaction after successful processes: %v", round, err)
		}
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
	for _, file := range []string{path, path + ".lock", path + ".anchor", path + ".init"} {
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
		for _, file := range []string{path, path + ".lock", path + ".anchor", path + ".init"} {
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

// TestFileReplayConcurrentProcessHelper is invoked only by the multi-process
// initialization regression above.
func TestFileReplayConcurrentProcessHelper(t *testing.T) {
	path := os.Getenv("WEDECENT_REPLAY_PROCESS_PATH")
	if path == "" {
		return
	}
	barrier := os.Getenv("WEDECENT_REPLAY_PROCESS_BARRIER")
	deadline := time.Now().Add(20 * time.Second)
	for {
		_, err := os.Stat(barrier)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for concurrent replay process barrier")
		}
		time.Sleep(5 * time.Millisecond)
	}

	expiry, err := strconv.ParseInt(os.Getenv("WEDECENT_REPLAY_PROCESS_EXPIRY"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := os.Getenv("WEDECENT_REPLAY_PROCESS_JTI")
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, time.UnixMilli(expiry)); err != nil {
		t.Fatalf("concurrent replay initialization/consumption failed: %v", err)
	}
}

func TestFileReplayRecoversPendingInitializationAfterProcessTermination(t *testing.T) {
	path := newReplayTestPath(t)
	startAndTerminateReplayInitializationProcess(t, path, "after_marker")

	marker, err := readReplayInitializationLocked(path+".init", testInitiator)
	if err != nil {
		t.Fatalf("read initialization marker left by terminated process: %v", err)
	}
	if marker.Status != "pending" {
		t.Fatalf("initialization status = %q, want pending", marker.Status)
	}
	for _, file := range []string{path + ".init", path + ".lock"} {
		if err := secureReplayFile(file); err != nil {
			t.Fatalf("crash-left metadata %s is not private: %v", filepath.Base(file), err)
		}
	}

	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("crashrecover0001"))
	expiry := time.Now().UTC().Add(time.Minute)
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, expiry); err != nil {
		t.Fatalf("recover pending initialization after process termination: %v", err)
	}
	if err := replay.ConsumePortForwardAuthorization(context.Background(), jti, expiry); !errors.Is(err, ErrAuthorizationReplay) {
		t.Fatalf("recovered authorization replay error = %v, want replay", err)
	}
	ready, err := readReplayInitializationLocked(path+".init", testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Status != "ready" {
		t.Fatalf("recovered initialization status = %q, want ready", ready.Status)
	}
}

func TestFileReplayRejectsInitializationInterruptedBeforeMarker(t *testing.T) {
	path := newReplayTestPath(t)
	startAndTerminateReplayInitializationProcess(t, path, "before_marker")

	if err := secureReplayFile(path + ".lock"); err != nil {
		t.Fatalf("orphaned initialization lock is not private: %v", err)
	}
	for _, file := range []string{path, path + ".init", path + ".anchor", path + ".pending"} {
		if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected pre-marker artifact %s: %v", filepath.Base(file), err)
		}
	}

	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString([]byte("crashbeforemark1"))
	err = replay.ConsumePortForwardAuthorization(context.Background(), jti, time.Now().UTC().Add(time.Minute))
	if !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("interrupted pre-marker initialization error = %v, want fail-closed replay unavailable", err)
	}
}

func TestFileReplayRejectsMalformedInitializationMetadata(t *testing.T) {
	for _, target := range []string{"marker", "pending"} {
		t.Run(target, func(t *testing.T) {
			path := newReplayTestPath(t)
			if err := ensureReplayInitialization(path, testInitiator, false); err != nil {
				t.Fatal(err)
			}
			metadataPath := path + ".init"
			if target == "pending" {
				metadataPath = path + ".pending"
			}
			if err := os.WriteFile(metadataPath, []byte("{malformed"), 0o600); err != nil {
				t.Fatal(err)
			}

			replay, err := NewFileReplay(path, testInitiator)
			if err != nil {
				t.Fatal(err)
			}
			err = replay.ConsumePortForwardAuthorization(
				context.Background(),
				base64.RawURLEncoding.EncodeToString([]byte("malformedstate01")),
				time.Now().UTC().Add(time.Minute),
			)
			if !errors.Is(err, ErrReplayUnavailable) {
				t.Fatalf("malformed %s error = %v, want fail-closed replay unavailable", target, err)
			}
		})
	}
}

func TestFileReplayRejectsPartialInitializationWithoutMarker(t *testing.T) {
	path := newReplayTestPath(t)
	if err := writeReplayAnchor(path+".anchor", replayAnchor{
		Version: replayStoreVersion, DeviceID: string(testInitiator), Generation: 0,
	}); err != nil {
		t.Fatal(err)
	}
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	err = replay.ConsumePortForwardAuthorization(
		context.Background(),
		base64.RawURLEncoding.EncodeToString([]byte("partialstate0001")),
		time.Now().UTC().Add(time.Minute),
	)
	if !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("partial initialization without marker error = %v, want fail-closed replay unavailable", err)
	}
}

func startAndTerminateReplayInitializationProcess(t *testing.T, path, mode string) {
	t.Helper()
	readyPath := path + ".child-ready"
	stopPath := readyPath + ".stop"
	var output bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestFileReplayInitializationCrashHelper$")
	cmd.Env = append(os.Environ(),
		"WEDECENT_REPLAY_CRASH_PATH="+path,
		"WEDECENT_REPLAY_CRASH_READY="+readyPath,
		"WEDECENT_REPLAY_CRASH_STOP="+stopPath,
		"WEDECENT_REPLAY_CRASH_MODE="+mode,
	)
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start initialization crash helper (%s): %v", mode, err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = os.Remove(stopPath)
	})

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect initialization crash helper readiness: %v", err)
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			waitErr := cmd.Wait()
			t.Fatalf("initialization crash helper (%s) did not reach barrier: wait=%v output=%s", mode, waitErr, output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := os.WriteFile(stopPath, []byte("stop"), 0o600); err != nil {
		t.Fatalf("signal initialization crash helper (%s): %v", mode, err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatalf("initialization crash helper (%s) exited normally, expected abrupt exit", mode)
	}
	if err := os.Remove(readyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove crash helper readiness marker: %v", err)
	}
	if err := os.Remove(stopPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove crash helper stop marker: %v", err)
	}
}

func TestFileReplayInitializationCrashHelper(t *testing.T) {
	mode := os.Getenv("WEDECENT_REPLAY_CRASH_MODE")
	if mode == "" {
		return
	}
	path := os.Getenv("WEDECENT_REPLAY_CRASH_PATH")
	readyPath := os.Getenv("WEDECENT_REPLAY_CRASH_READY")
	stopPath := os.Getenv("WEDECENT_REPLAY_CRASH_STOP")
	if path == "" || readyPath == "" || stopPath == "" {
		t.Fatal("initialization crash helper requires path and readiness/stop markers")
	}

	switch mode {
	case "before_marker":
		unlock, created, err := lockReplayFileOS(path)
		if err != nil {
			t.Fatalf("create initialization lock before marker: %v", err)
		}
		if !created {
			t.Fatal("expected initialization helper to create lock file")
		}
		defer unlock()
	case "after_marker":
		if err := ensureReplayInitialization(path, testInitiator, false); err != nil {
			t.Fatalf("publish pending initialization marker: %v", err)
		}
	default:
		t.Fatalf("unsupported initialization crash mode %q", mode)
	}
	if err := os.WriteFile(readyPath, []byte(mode), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(stopPath); err == nil {
			os.Exit(23)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect crash helper stop marker: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestFileReplayPairedSnapshotAnchorRollbackDocumentsSameAccountGap(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().UTC().Add(time.Minute)
	firstJTI := base64.RawURLEncoding.EncodeToString([]byte("rollbackfirst001"))
	secondJTI := base64.RawURLEncoding.EncodeToString([]byte("rollbacksecond01"))

	if err := replay.ConsumePortForwardAuthorization(context.Background(), firstJTI, expiry); err != nil {
		t.Fatalf("consume first authorization: %v", err)
	}
	olderSnapshot, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	olderAnchor, err := os.ReadFile(path + ".anchor")
	if err != nil {
		t.Fatal(err)
	}
	if err := replay.ConsumePortForwardAuthorization(context.Background(), secondJTI, expiry); err != nil {
		t.Fatalf("consume second authorization: %v", err)
	}

	// Simulate an attacker who can write as the service account restoring both
	// mutually consistent files. File permissions and the generation comparison
	// cannot distinguish this paired rollback from the earlier valid state.
	if err := os.WriteFile(path, olderSnapshot, 0o600); err != nil {
		t.Fatalf("restore older replay snapshot: %v", err)
	}
	if err := os.WriteFile(path+".anchor", olderAnchor, 0o600); err != nil {
		t.Fatalf("restore matching older replay anchor: %v", err)
	}

	err = replay.ConsumePortForwardAuthorization(context.Background(), secondJTI, expiry)
	if err != nil {
		t.Fatalf("paired snapshot-and-anchor rollback was unexpectedly detected: %v", err)
	}
	t.Log("SECURITY GAP: same-account paired rollback replayed a previously consumed authorization; an independent monotonic authority is required to prevent this threat")
}
func TestFileReplayCleansOrphanedStagingFilesAndPreservesDurablePendingState(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	firstJTI := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	pendingJTI := base64.RawURLEncoding.EncodeToString([]byte("pendingstate0001"))
	nextJTI := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	expiry := time.Now().UTC().Add(time.Minute)
	if err := replay.ConsumePortForwardAuthorization(context.Background(), firstJTI, expiry); err != nil {
		t.Fatalf("initialize replay store: %v", err)
	}

	snapshot, err := readReplaySnapshot(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	pendingEntries := make(map[string]int64, len(snapshot.Entries)+1)
	for jti, expiresAt := range snapshot.Entries {
		pendingEntries[jti] = expiresAt
	}
	pendingEntries[pendingJTI] = expiry.UnixMilli()
	if err := writeReplayPending(path, testInitiator, snapshot.Generation+1, pendingEntries); err != nil {
		t.Fatalf("publish durable pending transaction: %v", err)
	}

	var orphaned []string
	for _, kind := range []string{"init", "anchor", "replay", "pending", "lock"} {
		orphaned = append(orphaned, createReplayStagingTestFile(t, path, kind))
	}
	otherStorePath := filepath.Join(filepath.Dir(path), "other-replay.json")
	otherStoreStaging := createReplayStagingTestFile(t, otherStorePath, "lock")

	if err := replay.ConsumePortForwardAuthorization(context.Background(), nextJTI, expiry); err != nil {
		t.Fatalf("consume after orphan cleanup and pending recovery: %v", err)
	}
	for _, tempPath := range orphaned {
		if _, err := os.Lstat(tempPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("orphaned staging file %s remains: %v", filepath.Base(tempPath), err)
		}
	}
	if _, err := os.Lstat(otherStoreStaging); err != nil {
		t.Fatalf("cleanup removed another replay store's staging file: %v", err)
	}
	if _, err := os.Lstat(path + ".pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("durable pending transaction was not recovered: %v", err)
	}

	recovered, err := readReplaySnapshot(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	for _, jti := range []string{firstJTI, pendingJTI, nextJTI} {
		if _, ok := recovered.Entries[jti]; !ok {
			t.Errorf("replay recovery lost committed JTI %s", jti)
		}
	}
	if recovered.Generation != snapshot.Generation+2 {
		t.Fatalf("replay generation = %d, want %d", recovered.Generation, snapshot.Generation+2)
	}
}

type replayTestCloser func() error

func (closer replayTestCloser) Close() error { return closer() }

func TestFileReplayStagingCleanupReportsRemovalFailures(t *testing.T) {
	path := newReplayTestPath(t)
	tempPath := createReplayStagingTestFile(t, path, "replay")
	unlock, _, err := lockReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	removeFailure := errors.New("injected staging removal failure")
	err = cleanupReplayStagingWith(path, func(string) error { return removeFailure })
	unlock()
	if !errors.Is(err, removeFailure) {
		t.Fatalf("staging cleanup error = %v, want injected removal failure", err)
	}
	if _, err := os.Stat(tempPath); err != nil {
		t.Fatalf("failed removal unexpectedly removed staging file: %v", err)
	}

	primaryFailure := errors.New("primary replay write failure")
	file, err := os.OpenFile(tempPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	joined := cleanupReplayTempWith(primaryFailure, file, tempPath, func(string) error {
		return removeFailure
	})
	if !errors.Is(joined, primaryFailure) || !errors.Is(joined, removeFailure) {
		t.Fatalf("cleanup did not preserve both primary and removal errors: %v", joined)
	}

	closeFailure := errors.New("injected temporary-file close failure")
	closePath := createReplayStagingTestFile(t, path, "pending")
	closed := false
	closeErr := cleanupReplayTempWith(primaryFailure, replayTestCloser(func() error {
		closed = true
		return closeFailure
	}), closePath, os.Remove)
	if !closed || !errors.Is(closeErr, primaryFailure) || !errors.Is(closeErr, closeFailure) {
		t.Fatalf("close failure was not joined with the primary error: %v", closeErr)
	}
	if _, err := os.Lstat(closePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary file was not removed after injected close failure: %v", err)
	}
}

func TestFileReplayStagingCleanupRejectsUnexpectedEntriesWithoutChangingState(t *testing.T) {
	tests := []struct {
		name      string
		entry     string
		directory bool
	}{
		{name: "unknown_kind", entry: "unexpected-123"},
		{name: "malformed_suffix", entry: "init-!!!"},
		{name: "non_regular_entry", entry: "replay-123", directory: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := newReplayTestPath(t)
			replay, err := NewFileReplay(path, testInitiator)
			if err != nil {
				t.Fatal(err)
			}
			firstJTI := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
			nextJTI := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
			expiry := time.Now().UTC().Add(time.Minute)
			if err := replay.ConsumePortForwardAuthorization(context.Background(), firstJTI, expiry); err != nil {
				t.Fatal(err)
			}
			before, err := readReplaySnapshot(path, testInitiator)
			if err != nil {
				t.Fatal(err)
			}

			entryPath := filepath.Join(filepath.Dir(path), replayStagingPrefix(path)+test.entry)
			if test.directory {
				if err := os.Mkdir(entryPath, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(entryPath, []byte("unexpected staging metadata"), 0o600); err != nil {
				t.Fatal(err)
			}

			err = replay.ConsumePortForwardAuthorization(context.Background(), nextJTI, expiry)
			if !errors.Is(err, ErrReplayUnavailable) {
				t.Fatalf("malformed staging entry error = %v, want fail-closed ErrReplayUnavailable", err)
			}
			after, err := readReplaySnapshot(path, testInitiator)
			if err != nil {
				t.Fatal(err)
			}
			if after.Generation != before.Generation || len(after.Entries) != len(before.Entries) {
				t.Fatalf("malformed staging entry changed replay state: before=%#v after=%#v", before, after)
			}
			if _, ok := after.Entries[firstJTI]; !ok {
				t.Fatal("malformed staging entry cleanup lost existing replay state")
			}
			if _, ok := after.Entries[nextJTI]; ok {
				t.Fatal("authorization was consumed despite malformed staging metadata")
			}
			if _, err := os.Lstat(entryPath); err != nil {
				t.Fatalf("unexpected staging entry was removed: %v", err)
			}
		})
	}
}

func TestFileReplayConcurrentInitializationAndStagingCleanup(t *testing.T) {
	path := newReplayTestPath(t)
	orphan := createReplayStagingTestFile(t, path, "anchor")
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
		t.Fatalf("concurrent initialization/cleanup failures: %v", failures)
	}
	snapshot, err := readReplaySnapshot(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != workers || snapshot.Generation != workers {
		t.Fatalf("concurrent replay state entries=%d generation=%d, want %d", len(snapshot.Entries), snapshot.Generation, workers)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("concurrent cleanup left orphan staging file: %v", err)
	}
}

func TestFileReplayStagingCleanupWaitsForActiveStoreLock(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	firstJTI := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), firstJTI, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	unlock, _, err := lockReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	activeStaging := createReplayStagingTestFile(t, path, "replay")
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		done <- replay.ConsumePortForwardAuthorization(
			context.Background(),
			base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210")),
			time.Now().UTC().Add(time.Minute),
		)
	}()
	<-started

	deadline := time.Now().Add(5 * time.Second)
	for {
		replayProcessLocks.Lock()
		lock := replayProcessLocks.byPath[filepath.Clean(path)]
		refs := 0
		if lock != nil {
			refs = lock.refs
		}
		replayProcessLocks.Unlock()
		if refs >= 2 {
			break
		}
		if time.Now().After(deadline) {
			unlock()
			<-done
			t.Fatal("concurrent replay operation did not wait on the held store lock")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-done:
		unlock()
		t.Fatalf("replay operation completed while store lock was held: %v", err)
	default:
	}
	if _, err := os.Stat(activeStaging); err != nil {
		unlock()
		<-done
		t.Fatalf("active staging file was removed before lock release: %v", err)
	}

	unlock()
	if err := <-done; err != nil {
		t.Fatalf("replay operation after lock release: %v", err)
	}
	if _, err := os.Lstat(activeStaging); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan staging file was not cleaned after lock release: %v", err)
	}
}

func TestFileReplayStagingCleanupWaitsForCrossProcessActiveStaging(t *testing.T) {
	path := newReplayTestPath(t)
	replay, err := NewFileReplay(path, testInitiator)
	if err != nil {
		t.Fatal(err)
	}
	firstJTI := base64.RawURLEncoding.EncodeToString([]byte("crossprocfirst01"))
	if err := replay.ConsumePortForwardAuthorization(context.Background(), firstJTI, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	readyPath := path + ".active-ready"
	stopPath := path + ".active-stop"
	var output bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestFileReplayCrossProcessStagingLockHelper$")
	cmd.Env = append(os.Environ(),
		"WEDECENT_REPLAY_ACTIVE_PATH="+path,
		"WEDECENT_REPLAY_ACTIVE_READY="+readyPath,
		"WEDECENT_REPLAY_ACTIVE_STOP="+stopPath,
	)
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start cross-process staging holder: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = os.WriteFile(stopPath, []byte("stop"), 0o600)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = os.Remove(readyPath)
		_ = os.Remove(stopPath)
	})

	deadline := time.Now().Add(10 * time.Second)
	var activePath string
	for {
		data, readErr := os.ReadFile(readyPath)
		if readErr == nil {
			activePath = string(data)
			break
		}
		if !errors.Is(readErr, os.ErrNotExist) {
			t.Fatalf("read active staging readiness: %v", readErr)
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			waitErr := cmd.Wait()
			t.Fatalf("cross-process staging holder did not reach barrier: wait=%v output=%s", waitErr, output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if activePath == "" {
		t.Fatal("cross-process helper did not report its active staging path")
	}

	done := make(chan error, 1)
	go func() {
		done <- replay.ConsumePortForwardAuthorization(
			context.Background(),
			base64.RawURLEncoding.EncodeToString([]byte("crossprocnext001")),
			time.Now().UTC().Add(time.Minute),
		)
	}()
	deadline = time.Now().Add(5 * time.Second)
	for {
		replayProcessLocks.Lock()
		lock := replayProcessLocks.byPath[filepath.Clean(path)]
		refs := 0
		if lock != nil {
			refs = lock.refs
		}
		replayProcessLocks.Unlock()
		if refs > 0 {
			break
		}
		if time.Now().After(deadline) {
			_ = os.WriteFile(stopPath, []byte("stop"), 0o600)
			_ = cmd.Wait()
			<-done
			t.Fatal("parent replay operation did not enter the cross-process lock path")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		_ = os.WriteFile(stopPath, []byte("stop"), 0o600)
		_ = cmd.Wait()
		t.Fatalf("replay cleanup completed while another process held the store lock: %v", err)
	default:
	}
	if _, err := os.Stat(activePath); err != nil {
		_ = os.WriteFile(stopPath, []byte("stop"), 0o600)
		_ = cmd.Wait()
		<-done
		t.Fatalf("active staging file disappeared before cross-process lock release: %v", err)
	}

	if err := os.WriteFile(stopPath, []byte("stop"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("cross-process staging holder exited normally, expected abrupt process exit")
	}
	if err := <-done; err != nil {
		t.Fatalf("replay operation after cross-process lock release: %v", err)
	}
	if _, err := os.Lstat(activePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan staging file was not removed after cross-process lock release: %v", err)
	}
}

func TestFileReplayCrossProcessStagingLockHelper(t *testing.T) {
	path := os.Getenv("WEDECENT_REPLAY_ACTIVE_PATH")
	if path == "" {
		return
	}
	readyPath := os.Getenv("WEDECENT_REPLAY_ACTIVE_READY")
	stopPath := os.Getenv("WEDECENT_REPLAY_ACTIVE_STOP")
	if readyPath == "" || stopPath == "" {
		t.Fatal("cross-process staging helper requires readiness and stop paths")
	}
	unlock, _, err := lockReplayFile(path)
	if err != nil {
		t.Fatalf("acquire cross-process replay lock: %v", err)
	}
	defer unlock()
	file, err := os.CreateTemp(filepath.Dir(path), replayStagingPattern(path, "replay"))
	if err != nil {
		t.Fatalf("create active replay staging file: %v", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := setReplayFileOwner(file.Name()); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := secureReplayFile(file.Name()); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("active cross-process staging file")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := os.WriteFile(readyPath, []byte(file.Name()), 0o600); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(stopPath); err == nil {
			os.Exit(23)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect cross-process stop marker: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func createReplayStagingTestFile(t *testing.T, path, kind string) string {
	t.Helper()
	file, err := os.CreateTemp(filepath.Dir(path), replayStagingPattern(path, kind))
	if err != nil {
		t.Fatalf("create %s replay staging fixture: %v", kind, err)
	}
	if _, err := file.Write([]byte("interrupted staging contents")); err != nil {
		closeErr := file.Close()
		t.Fatalf("write %s replay staging fixture: %v (close: %v)", kind, err, closeErr)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close %s replay staging fixture: %v", kind, err)
	}
	return file.Name()
}

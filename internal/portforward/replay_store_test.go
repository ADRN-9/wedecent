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
	path := filepath.Join(t.TempDir(), "portforward-replay.json")
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

func TestFileReplayConsumptionIsAtomicAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portforward-replay.json")
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

func TestFileReplayPrunesExpiredEntriesAndRejectsExpiredConsumption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portforward-replay.json")
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

func TestFileReplayRejectsWrongDeviceScopeAndCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portforward-replay.json")
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

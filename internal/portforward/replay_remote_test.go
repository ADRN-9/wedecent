package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
)

type remoteReplayTestRequest struct {
	DeviceID            string        `json:"device_id"`
	Authorization       Authorization `json:"authorization"`
	AuthorizationSHA256 string        `json:"authorization_sha256"`
	DeviceSignature     string        `json:"device_signature"`
}

func newRemoteReplayFixture(t *testing.T, handler http.Handler) (*RemoteReplay, Authorization, ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	devicePublic, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.InitiatingDevice = mesh.DeviceID(identity.DeviceID(devicePublic))
	claims.Route.Source = claims.InitiatingDevice
	claims.Route.Hops[0].From = claims.InitiatingDevice
	authorization, err := SignAuthorization(controlPrivate, claims)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	replay, err := NewRemoteReplay(server.URL+"/functions/v1/port-forward-replay", "public-anon-key", mesh.DeviceID(identity.DeviceID(devicePublic)), devicePrivate)
	if err != nil {
		t.Fatal(err)
	}
	replay.Now = func() time.Time { return now }
	return replay, authorization, devicePublic, controlPublic
}

func verifyRemoteReplayTestRequest(t *testing.T, request remoteReplayTestRequest, publicKey ed25519.PublicKey) {
	t.Helper()
	if request.DeviceID != identity.DeviceID(publicKey) {
		t.Fatalf("device_id = %q", request.DeviceID)
	}
	message, err := canonicalMessage(request.Authorization.KeyID, request.Authorization.Claims)
	if err != nil {
		t.Fatal(err)
	}
	capabilitySignature, err := base64.RawURLEncoding.Strict().DecodeString(request.Authorization.Signature)
	if err != nil {
		t.Fatal(err)
	}
	digestInput := append(append([]byte(nil), message...), capabilitySignature...)
	digest := sha256.Sum256(digestInput)
	if request.AuthorizationSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("authorization digest did not bind canonical claims and signature")
	}
	deviceMessage := remoteReplayDeviceMessage(mesh.DeviceID(request.DeviceID), request.Authorization.Claims.JTI, request.Authorization.Claims.ExpiresAtUnixMS, digest)
	deviceSignature, err := base64.RawURLEncoding.Strict().DecodeString(request.DeviceSignature)
	if err != nil || !ed25519.Verify(publicKey, deviceMessage, deviceSignature) {
		t.Fatal("device replay proof signature is invalid")
	}
}

func TestRemoteReplayCanonicalMessageMatchesGoFixture(t *testing.T) {
	issued := time.Date(2027, 1, 15, 8, 0, 0, 0, time.UTC)
	claims := testClaims(issued, DirectionLocal)
	message, err := canonicalMessage("ed25519-fixture-key", claims)
	if err != nil {
		t.Fatal(err)
	}
	const want = "AAAAGHdlZGVjZW50LXBvcnQtZm9yd2FyZC12MQAAAAEAAAATZWQyNTUxOS1maXh0dXJlLWtleQAAABZ3ZWRlY2VudC1jb250cm9sLXBsYW5lAAAAF3dlZGVjZW50LXBvcnQtZm9yd2FyZGVyAAAAEnBvcnRfZm9yd2FyZC5sb2NhbAAAABZNREV5TXpRMU5qYzRPV0ZpWTJSbFpnAAAAJDAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMQAAAAVsb2NhbAAAABN3ZF9hYWFhYWFhYWFhYWFhYWFhAAAAE3dkX2JiYmJiYmJiYmJiYmJiYmIAAAAAAAAAJDAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMgAAABN3ZF9hYWFhYWFhYWFhYWFhYWFhAAAAE3dkX2JiYmJiYmJiYmJiYmJiYmIAAAALZXhhbXBsZS5jb20AAAAJMTI3LjAuMC4xAAAACGxvb3BiYWNrAAAAA3RjcAAAAaMYXFAAAAABoxhdr5AAAAAAAAABuwAAAAAAAKhzAAAAAAAAAAQAAAAAAAAAeAAAAAAAAAAeAAAAAQAAABN3ZF9hYWFhYWFhYWFhYWFhYWFhAAAAE3dkX2JiYmJiYmJiYmJiYmJiYmIAAAAIaW50ZXJuZXQAAAAAAAAADA"
	if got := base64.RawURLEncoding.EncodeToString(message); got != want {
		t.Fatalf("canonical message fixture mismatch:\n got %s\nwant %s", got, want)
	}
	digestInput := append(append([]byte(nil), message...), bytes.Repeat([]byte{1}, ed25519.SignatureSize)...)
	digest := sha256.Sum256(digestInput)
	if got := hex.EncodeToString(digest[:]); got != "050c6b5504afa088641d4b7f877450ee8f67c8cd2820fa0fb350713a503877d0" {
		t.Fatalf("authorization digest fixture = %s", got)
	}
}

func TestRemoteReplaySendsVerifiedCapabilityAndDeviceProof(t *testing.T) {
	var devicePublic ed25519.PublicKey
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/functions/v1/port-forward-replay" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("apikey") != "public-anon-key" {
			t.Fatal("public Data API key was not sent")
		}
		var body remoteReplayTestRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		verifyRemoteReplayTestRequest(t, body, devicePublic)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":true,"generation":"1","state_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	})
	replay, authorization, publicKey, controlPublic := newRemoteReplayFixture(t, handler)
	devicePublic = publicKey
	verifier := AuthorizationVerifier{PublicKey: controlPublic, Replay: replay}
	if _, err := verifier.VerifyAndConsume(context.Background(), authorization); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteReplayRejectsJTIAfterPairedLocalSnapshotAnchorRollback(t *testing.T) {
	var devicePublic ed25519.PublicKey
	var mu sync.Mutex
	consumed := make(map[string]bool)
	var generation uint64
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body remoteReplayTestRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		verifyRemoteReplayTestRequest(t, body, devicePublic)
		mu.Lock()
		defer mu.Unlock()
		jti := body.Authorization.Claims.JTI
		if consumed[jti] {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"accepted":false,"reason":"replay"}`))
			return
		}
		consumed[jti] = true
		generation++
		_, _ = fmt.Fprintf(w, `{"accepted":true,"generation":"%d","state_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`, generation)
	})
	remote, _, publicKey, _ := newRemoteReplayFixture(t, handler)
	devicePublic = publicKey
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := remote.Now().UTC()
	makeAuthorization := func(jti string) Authorization {
		claims := testClaims(now, DirectionLocal)
		claims.InitiatingDevice = remote.DeviceID
		claims.Route.Source = remote.DeviceID
		claims.Route.Hops[0].From = remote.DeviceID
		claims.JTI = base64.RawURLEncoding.EncodeToString([]byte(jti))
		authorization, signErr := SignAuthorization(controlPrivate, claims)
		if signErr != nil {
			t.Fatal(signErr)
		}
		return authorization
	}
	authorizationA := makeAuthorization("replayauth000001")
	authorizationB := makeAuthorization("replayauth000002")
	if _, err := AuthorizationVerifier{PublicKey: controlPublic, Replay: remote, Now: func() time.Time { return now }}.VerifyAndConsume(context.Background(), authorizationA); err != nil {
		t.Fatalf("consume A through independent authority: %v", err)
	}

	localPath := filepath.Join(t.TempDir(), "portforward-replay.json")
	local, err := NewFileReplay(localPath, remote.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := local.ConsumePortForwardAuthorization(context.Background(), authorizationA.Claims.JTI, time.UnixMilli(authorizationA.Claims.ExpiresAtUnixMS)); err != nil {
		t.Fatalf("save local snapshot after A: %v", err)
	}
	oldSnapshot, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	oldAnchor, err := os.ReadFile(localPath + ".anchor")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := AuthorizationVerifier{PublicKey: controlPublic, Replay: remote, Now: func() time.Time { return now }}.VerifyAndConsume(context.Background(), authorizationB); err != nil {
		t.Fatalf("consume B through independent authority: %v", err)
	}
	if err := local.ConsumePortForwardAuthorization(context.Background(), authorizationB.Claims.JTI, time.UnixMilli(authorizationB.Claims.ExpiresAtUnixMS)); err != nil {
		t.Fatalf("save local snapshot after B: %v", err)
	}

	// Restore the mutually consistent local snapshot and anchor from after A.
	if err := os.WriteFile(localPath, oldSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath+".anchor", oldAnchor, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := local.ConsumePortForwardAuthorization(context.Background(), authorizationB.Claims.JTI, time.UnixMilli(authorizationB.Claims.ExpiresAtUnixMS)); err != nil {
		t.Fatalf("historical file store should demonstrate paired rollback acceptance: %v", err)
	}
	if _, err := AuthorizationVerifier{PublicKey: controlPublic, Replay: remote, Now: func() time.Time { return now }}.VerifyAndConsume(context.Background(), authorizationB); !errors.Is(err, ErrAuthorizationReplay) {
		t.Fatalf("independent authority accepted B after paired local rollback: %v", err)
	}
}

func TestRemoteReplayRejectsBareJTIAndDuplicate(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"accepted":false,"reason":"replay"}`))
	})
	replay, authorization, _, _ := newRemoteReplayFixture(t, handler)
	if err := replay.ConsumePortForwardAuthorization(context.Background(), authorization.Claims.JTI, time.UnixMilli(authorization.Claims.ExpiresAtUnixMS)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("bare JTI consume error = %v", err)
	}
	if err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrAuthorizationReplay) {
		t.Fatalf("duplicate consume error = %v", err)
	}
}

func TestRemoteReplayFailsClosedOnUnavailableAuthority(t *testing.T) {
	replay, authorization, _, _ := newRemoteReplayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	if err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("unavailable authority error = %v", err)
	}
}

func TestRemoteReplayConcurrentConsumptionAndRestart(t *testing.T) {
	var mu sync.Mutex
	consumed := make(map[string]bool)
	var devicePublic ed25519.PublicKey
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body remoteReplayTestRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		verifyRemoteReplayTestRequest(t, body, devicePublic)
		mu.Lock()
		_, exists := consumed[body.Authorization.Claims.JTI]
		if !exists {
			consumed[body.Authorization.Claims.JTI] = true
		}
		mu.Unlock()
		if exists {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"accepted":false}`))
			return
		}
		_, _ = w.Write([]byte(`{"accepted":true,"generation":"1","state_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
	})
	replay, authorization, publicKey, _ := newRemoteReplayFixture(t, handler)
	devicePublic = publicKey
	const attempts = 32
	var successes atomic.Int32
	var replays atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrAuthorizationReplay):
				replays.Add(1)
			default:
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || replays.Load() != attempts-1 {
		t.Fatalf("successes=%d replays=%d", successes.Load(), replays.Load())
	}
	restarted, err := NewRemoteReplay(replay.Endpoint, replay.APIKey, replay.DeviceID, replay.Signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrAuthorizationReplay) {
		t.Fatalf("post-restart replay error = %v", err)
	}
}

func TestRemoteReplayAmbiguousCommitFailsClosedAndRetryDetectsReplay(t *testing.T) {
	var committed atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if committed.CompareAndSwap(false, true) {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("test server does not support connection hijacking")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"accepted":false}`))
	})
	replay, authorization, _, _ := newRemoteReplayFixture(t, handler)
	if err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("ambiguous commit error = %v", err)
	}
	if err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrAuthorizationReplay) {
		t.Fatalf("retry after ambiguous commit error = %v", err)
	}
}

func TestRemoteReplayRejectsUnsafeEndpointAndWrongDeviceKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := mesh.DeviceID(identity.DeviceID(publicKey))
	for _, endpoint := range []string{
		"http://example.com/functions/v1/port-forward-replay",
		"https://example.com/other",
		"https://user:pass@example.com/functions/v1/port-forward-replay",
		"https://example.com/functions/v1/port-forward-replay?redirect=1",
	} {
		if _, err := NewRemoteReplay(endpoint, "public-anon-key", deviceID, privateKey); !errors.Is(err, ErrReplayUnavailable) {
			t.Fatalf("endpoint %q error = %v", endpoint, err)
		}
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRemoteReplay("https://example.com/functions/v1/port-forward-replay", "public-anon-key", deviceID, otherPrivate); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("wrong signer error = %v", err)
	}
}

func TestRemoteReplayRejectsRedirectWithoutForwardingProof(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, target.URL+"/functions/v1/port-forward-replay", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	replay, authorization, _, _ := newRemoteReplayFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	replay.Endpoint = source.URL + "/functions/v1/port-forward-replay"
	if err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("redirect error = %v", err)
	}
	if redirected.Load() {
		t.Fatal("signed replay request followed a redirect")
	}
}

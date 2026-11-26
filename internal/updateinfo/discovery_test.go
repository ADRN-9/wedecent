package updateinfo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type discoveryFixture struct {
	now time.Time
	rootPublic ed25519.PublicKey
	rootPrivate ed25519.PrivateKey
	manifestPrivate ed25519.PrivateKey
	keyset Keyset
	keysetBody []byte
	keysetSignature []byte
	manifest Manifest
	manifestBody []byte
	manifestSignature []byte
}

func newDiscoveryFixture(t *testing.T) discoveryFixture {
	t.Helper()
	now := time.Date(2026, 9, 23, 20, 30, 0, 0, time.UTC)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	manifestPublic, manifestPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	encodedPublic, err := EncodePublicKey(manifestPublic)
	if err != nil { t.Fatal(err) }
	keyset := Keyset{
		Schema: KeysetSchemaV1, Epoch: 7, RootKeyID: "wedecent-update-root-1",
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(24*time.Hour).Format(time.RFC3339),
		Keys: []KeysetEntry{{
			ID: "stable-2026-01", PublicKey: strings.TrimSuffix(string(encodedPublic), "\n"),
			NotBefore: now.Add(-time.Hour).Format(time.RFC3339),
			NotAfter: now.Add(12*time.Hour).Format(time.RFC3339), Status: "active",
		}},
	}
	keysetBody, err := EncodeCanonicalKeyset(keyset, now)
	if err != nil { t.Fatal(err) }
	keysetSignature, err := EncodeSignature(ed25519.Sign(rootPrivate, keysetBody))
	if err != nil { t.Fatal(err) }
	manifest := validManifest()
	manifest.Schema = ManifestSchemaV2
	manifest.SigningKeyID = keyset.Keys[0].ID
	manifest.KeysetEpoch = keyset.Epoch
	manifest.PublishedAt = now.Format(time.RFC3339)
	manifestBody, err := EncodeCanonical(manifest)
	if err != nil { t.Fatal(err) }
	manifestSignature, err := EncodeSignature(ed25519.Sign(manifestPrivate, manifestBody))
	if err != nil { t.Fatal(err) }
	return discoveryFixture{now, rootPublic, rootPrivate, manifestPrivate, keyset, keysetBody, keysetSignature, manifest, manifestBody, manifestSignature}
}

func response(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body))}
}

func (f discoveryFixture) transport(t *testing.T, mutate func(string, []byte) ([]byte, int)) http.RoundTripper {
	t.Helper()
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body []byte
		switch req.URL.String() {
		case StableKeysetURL: body = f.keysetBody
		case StableKeysetSignatureURL: body = f.keysetSignature
		case StableManifestURL: body = f.manifestBody
		case StableSignatureURL: body = f.manifestSignature
		default: return nil, errors.New("unexpected URL: " + req.URL.String())
		}
		status := http.StatusOK
		if mutate != nil { body, status = mutate(req.URL.String(), body) }
		return response(status, body), nil
	})
}

func newDiscoveryClient(t *testing.T, f discoveryFixture, transport http.RoundTripper) (DiscoveryClient, *StateStore) {
	t.Helper()
	store := NewStateStore(StatePath(filepath.Join(t.TempDir(), "client")))
	client := DiscoveryClient{
		RootKeyID: f.keyset.RootKeyID, RootPublicKey: f.rootPublic,
		State: store, Transport: transport, Now: func() time.Time { return f.now },
	}
	return client, store
}

func TestDiscoverStableUsesRootKeysetAndV2Only(t *testing.T) {
	f := newDiscoveryFixture(t)
	var mu sync.Mutex
	var requested []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		requested = append(requested, req.URL.String())
		mu.Unlock()
		switch req.URL.String() {
		case StableKeysetURL: return response(http.StatusOK, f.keysetBody), nil
		case StableKeysetSignatureURL: return response(http.StatusOK, f.keysetSignature), nil
		case StableManifestURL: return response(http.StatusOK, f.manifestBody), nil
		case StableSignatureURL: return response(http.StatusOK, f.manifestSignature), nil
		default: t.Fatalf("unexpected URL %q", req.URL.String()); return nil, errors.New("unexpected URL")
		}
	})
	client, store := newDiscoveryClient(t, f, transport)
	got, err := client.DiscoverStable(context.Background(), "v1.2.2", 41)
	if err != nil { t.Fatal(err) }
	if got != f.manifest { t.Fatalf("DiscoverStable() = %#v, want %#v", got, f.manifest) }
	mu.Lock()
	defer mu.Unlock()
	want := []string{StableKeysetURL, StableKeysetSignatureURL, StableManifestURL, StableSignatureURL}
	if len(requested) != len(want) { t.Fatalf("requested URLs = %#v", requested) }
	for i := range want { if requested[i] != want[i] { t.Fatalf("requested[%d] = %q, want %q", i, requested[i], want[i]) } }
	state, err := store.Load()
	if err != nil { t.Fatal(err) }
	if state.KeysetEpoch != f.keyset.Epoch || state.KeysetDigest == "" || state.StableSequence != 0 {
		t.Fatalf("discovery state = %#v; keyset should persist, sequence only after install", state)
	}
}

func TestDiscoverStableRequiresPinnedRootAndProtectedState(t *testing.T) {
	f := newDiscoveryFixture(t)
	called := false
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, errors.New("unexpected") })
	for name, client := range map[string]DiscoveryClient{
		"missing root": {State: NewStateStore(StatePath(filepath.Join(t.TempDir(), "client"))), Transport: transport},
		"missing state": {RootKeyID: f.keyset.RootKeyID, RootPublicKey: f.rootPublic, Transport: transport},
		"short root": {RootKeyID: f.keyset.RootKeyID, RootPublicKey: f.rootPublic[:ed25519.PublicKeySize-1], State: NewStateStore(StatePath(filepath.Join(t.TempDir(), "client"))), Transport: transport},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.DiscoverStable(context.Background(), "v1.2.2", 0); !errors.Is(err, ErrDiscovery) { t.Fatalf("error = %v, want ErrDiscovery", err) }
		})
	}
	if called { t.Fatal("network called without complete root/state trust configuration") }
}

func TestDiscoverStableRejectsManifestV1AndBadSignatures(t *testing.T) {
	f := newDiscoveryFixture(t)
	v1 := f.manifest
	v1.Schema, v1.SigningKeyID, v1.KeysetEpoch = ManifestSchemaV1, "", 0
	v1Body, err := EncodeCanonical(v1)
	if err != nil { t.Fatal(err) }
	tests := map[string]func(string, []byte) ([]byte, int){
		"v1 downgrade": func(url string, body []byte) ([]byte, int) { if url == StableManifestURL { return v1Body, http.StatusOK }; return body, http.StatusOK },
		"bad root signature": func(url string, body []byte) ([]byte, int) { if url == StableKeysetSignatureURL { copy := append([]byte(nil), body...); copy[0] ^= 1; return copy, http.StatusOK }; return body, http.StatusOK },
		"bad manifest signature": func(url string, body []byte) ([]byte, int) { if url == StableSignatureURL { copy := append([]byte(nil), body...); copy[0] ^= 1; return copy, http.StatusOK }; return body, http.StatusOK },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, _ := newDiscoveryClient(t, f, f.transport(t, mutate))
			_, err := client.DiscoverStable(context.Background(), "v1.2.2", 41)
			if err == nil { t.Fatal("downgrade or invalid signature was accepted") }
		})
	}
}

func TestDiscoverStableUsesPersistedSequenceAfterRestart(t *testing.T) {
	f := newDiscoveryFixture(t)
	statePath := StatePath(filepath.Join(t.TempDir(), "client"))
	first := NewStateStore(statePath)
	if err := first.Advance(f.manifest.Sequence); err != nil { t.Fatal(err) }
	restarted := NewStateStore(statePath)
	client := DiscoveryClient{RootKeyID: f.keyset.RootKeyID, RootPublicKey: f.rootPublic, State: restarted, Transport: f.transport(t, nil), Now: func() time.Time { return f.now }}
	if _, err := client.DiscoverStable(context.Background(), "v1.2.2", 0); !errors.Is(err, ErrRollback) {
		t.Fatalf("restart rollback error = %v, want ErrRollback", err)
	}
	state, err := restarted.Load()
	if err != nil { t.Fatal(err) }
	if state.StableSequence != f.manifest.Sequence { t.Fatalf("restart sequence = %d", state.StableSequence) }
}

func TestDiscoverStableRejectsExpiredKeysetAndPreservesNoDowngrade(t *testing.T) {
	f := newDiscoveryFixture(t)
	expired := f.now.Add(48*time.Hour)
	client, _ := newDiscoveryClient(t, f, f.transport(t, nil))
	client.Now = func() time.Time { return expired }
	if _, err := client.DiscoverStable(context.Background(), "v1.2.2", 41); !errors.Is(err, ErrInvalidKeyset) { t.Fatalf("expired keyset error = %v, want ErrInvalidKeyset", err) }
}

func TestDiscoverStableRejectsRedirectWithoutFollowing(t *testing.T) {
	f := newDiscoveryFixture(t)
	requests := 0
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		resp := response(http.StatusFound, nil)
		resp.Header.Set("Location", "https://evil.example/manifest.json")
		resp.Request = req
		return resp, nil
	})
	client, _ := newDiscoveryClient(t, f, transport)
	if _, err := client.DiscoverStable(context.Background(), "v1.2.2", 0); !errors.Is(err, ErrDiscovery) { t.Fatalf("error = %v, want ErrDiscovery", err) }
	if requests != 1 { t.Fatalf("request count = %d, want 1", requests) }
}

func TestDiscoverStableRejectsBadHTTPAndOversizedBodies(t *testing.T) {
	f := newDiscoveryFixture(t)
	tests := map[string]roundTripFunc{
		"status": func(*http.Request) (*http.Response, error) { return response(http.StatusServiceUnavailable, []byte("unavailable")), nil },
		"declared too large": func(*http.Request) (*http.Response, error) { resp := response(http.StatusOK, []byte("x")); resp.ContentLength = MaxKeysetBytes+1; return resp, nil },
		"streamed too large": func(*http.Request) (*http.Response, error) { body := make([]byte, MaxKeysetBytes+1); resp := response(http.StatusOK, body); resp.ContentLength = -1; return resp, nil },
	}
	for name, transport := range tests {
		t.Run(name, func(t *testing.T) {
			client, _ := newDiscoveryClient(t, f, transport)
			if _, err := client.DiscoverStable(context.Background(), "v1.2.2", 0); !errors.Is(err, ErrDiscovery) { t.Fatalf("error = %v, want ErrDiscovery", err) }
		})
	}
}

func TestDiscoverStablePreservesCancellationAndRejectsNegativeTimeout(t *testing.T) {
	f := newDiscoveryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) { <-req.Context().Done(); return nil, req.Context().Err() })
	client, _ := newDiscoveryClient(t, f, transport)
	if _, err := client.DiscoverStable(ctx, "v1.2.2", 0); !errors.Is(err, ErrDiscovery) || !errors.Is(err, context.Canceled) { t.Fatalf("cancellation error = %v", err) }
	client.Transport = f.transport(t, nil)
	client.Timeout = -time.Second
	if _, err := client.DiscoverStable(context.Background(), "v1.2.2", 0); !errors.Is(err, ErrDiscovery) { t.Fatalf("negative timeout error = %v", err) }
}

func TestDiscoverStableRejectsUntrustedStatePath(t *testing.T) {
	f := newDiscoveryFixture(t)
	path := filepath.Join(t.TempDir(), "missing", UpdateStateFilename)
	client := DiscoveryClient{RootKeyID: f.keyset.RootKeyID, RootPublicKey: f.rootPublic, State: NewStateStore(path), Transport: f.transport(t, nil), Now: func() time.Time { return f.now }}
	if _, err := client.DiscoverStable(context.Background(), "v1.2.2", 0); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unsafe state parent error = %v, want ErrInvalidState", err)
	}
	_ = os.ErrNotExist
}

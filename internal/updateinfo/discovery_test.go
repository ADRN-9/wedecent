package updateinfo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type discoveryFixture struct {
	now               time.Time
	rootPublic        ed25519.PublicKey
	rootPrivate       ed25519.PrivateKey
	manifestPrivate   ed25519.PrivateKey
	keyset            Keyset
	keysetBody        []byte
	keysetSignature   []byte
	manifest          Manifest
	manifestBody      []byte
	manifestSignature []byte
	pairBody          []byte
}

func newDiscoveryFixture(t *testing.T) discoveryFixture {
	t.Helper()

	now := time.Date(2026, 9, 23, 20, 30, 0, 0, time.UTC)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestPublic, manifestPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := EncodePublicKey(manifestPublic)
	if err != nil {
		t.Fatal(err)
	}

	keyset := Keyset{
		Schema:    KeysetSchemaV1,
		Epoch:     7,
		RootKeyID: "wedecent-update-root-1",
		IssuedAt:  now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		Keys: []KeysetEntry{{
			ID:        "stable-2026-01",
			PublicKey: strings.TrimSuffix(string(encodedPublic), "\n"),
			NotBefore: now.Add(-time.Hour).Format(time.RFC3339),
			NotAfter:  now.Add(12 * time.Hour).Format(time.RFC3339),
			Status:    "active",
		}},
	}
	keysetBody, err := EncodeCanonicalKeyset(keyset, now)
	if err != nil {
		t.Fatal(err)
	}
	keysetSignature, err := EncodeSignature(ed25519.Sign(rootPrivate, keysetBody))
	if err != nil {
		t.Fatal(err)
	}

	manifest := validManifest()
	manifest.Schema = ManifestSchemaV2
	manifest.SigningKeyID = keyset.Keys[0].ID
	manifest.KeysetEpoch = keyset.Epoch
	manifest.PublishedAt = now.Format(time.RFC3339)
	manifestBody, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestSignature, err := EncodeSignature(ed25519.Sign(manifestPrivate, manifestBody))
	if err != nil {
		t.Fatal(err)
	}
	pairBody, err := EncodeCanonicalStablePair(manifestBody, manifestSignature)
	if err != nil {
		t.Fatal(err)
	}

	return discoveryFixture{
		now:               now,
		rootPublic:        rootPublic,
		rootPrivate:       rootPrivate,
		manifestPrivate:   manifestPrivate,
		keyset:            keyset,
		keysetBody:        keysetBody,
		keysetSignature:   keysetSignature,
		manifest:          manifest,
		manifestBody:      manifestBody,
		manifestSignature: manifestSignature,
		pairBody:          pairBody,
	}
}

func response(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
	}
}

func (f discoveryFixture) transport(mutate func(string, []byte) ([]byte, int)) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body []byte
		keysetURL, keysetSignatureURL := stableKeysetURLs(f.keyset.Epoch)
		switch req.URL.String() {
		case StablePairURL:
			body = f.pairBody
		case keysetURL:
			body = f.keysetBody
		case keysetSignatureURL:
			body = f.keysetSignature
		default:
			return nil, errors.New("unexpected URL: " + req.URL.String())
		}
		status := http.StatusOK
		if mutate != nil {
			body, status = mutate(req.URL.String(), body)
		}
		return response(status, body), nil
	})
}

func newDiscoveryClient(t *testing.T, f discoveryFixture, transport http.RoundTripper) (DiscoveryClient, *StateStore) {
	t.Helper()
	store := NewStateStore(StatePath(filepath.Join(t.TempDir(), "client")))
	store.readInstalledVersion = func() (string, error) { return "v0.3.9", nil }
	client := DiscoveryClient{
		RootKeyID:     f.keyset.RootKeyID,
		RootPublicKey: f.rootPublic,
		State:         store,
		Transport:     transport,
		Now:           func() time.Time { return f.now },
	}
	return client, store
}

func TestDiscoverStableUsesRootKeysetAndV2Only(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	var mu sync.Mutex
	var requested []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		requested = append(requested, req.URL.String())
		mu.Unlock()
		keysetURL, keysetSignatureURL := stableKeysetURLs(fixture.keyset.Epoch)
		switch req.URL.String() {
		case StablePairURL:
			return response(http.StatusOK, fixture.pairBody), nil
		case keysetURL:
			return response(http.StatusOK, fixture.keysetBody), nil
		case keysetSignatureURL:
			return response(http.StatusOK, fixture.keysetSignature), nil
		default:
			return nil, errors.New("unexpected URL: " + req.URL.String())
		}
	})

	client, store := newDiscoveryClient(t, fixture, transport)
	got, err := client.DiscoverStable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != fixture.manifest {
		t.Fatalf("DiscoverStable() = %#v, want %#v", got, fixture.manifest)
	}

	mu.Lock()
	defer mu.Unlock()
	keysetURL, keysetSignatureURL := stableKeysetURLs(fixture.keyset.Epoch)
	wantURLs := []string{StablePairURL, keysetURL, keysetSignatureURL}
	if len(requested) != len(wantURLs) {
		t.Fatalf("requested URLs = %#v", requested)
	}
	for i := range wantURLs {
		if requested[i] != wantURLs[i] {
			t.Fatalf("requested[%d] = %q, want %q", i, requested[i], wantURLs[i])
		}
	}

	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.KeysetEpoch != fixture.keyset.Epoch || state.KeysetDigest == "" || state.StableSequence != 0 {
		t.Fatalf("discovery state = %#v; keyset should persist, sequence only after install", state)
	}
}

func TestDiscoverStableRequiresPinnedRootAndProtectedState(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	called := false
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected network request")
	})
	tests := map[string]DiscoveryClient{
		"missing root": {
			State:     NewStateStore(StatePath(filepath.Join(t.TempDir(), "client"))),
			Transport: transport,
		},
		"missing state": {
			RootKeyID:     fixture.keyset.RootKeyID,
			RootPublicKey: fixture.rootPublic,
			Transport:     transport,
		},
		"short root": {
			RootKeyID:     fixture.keyset.RootKeyID,
			RootPublicKey: fixture.rootPublic[:ed25519.PublicKeySize-1],
			State:         NewStateStore(StatePath(filepath.Join(t.TempDir(), "client"))),
			Transport:     transport,
		},
	}
	for name, client := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := client.DiscoverStable(context.Background()); !errors.Is(err, ErrDiscovery) {
				t.Fatalf("error = %v, want ErrDiscovery", err)
			}
		})
	}
	if called {
		t.Fatal("network called without complete root/state trust configuration")
	}
}

func TestDiscoverStableRejectsManifestV1AndBadSignatures(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	v1 := fixture.manifest
	v1.Schema = ManifestSchemaV1
	v1.SigningKeyID = ""
	v1.KeysetEpoch = 0
	v1Body, err := EncodeCanonical(v1)
	if err != nil {
		t.Fatal(err)
	}
	v1Signature := ed25519.Sign(fixture.manifestPrivate, v1Body)
	v1Envelope, err := json.Marshal(StablePairEnvelope{
		Schema:    StablePairSchema,
		Manifest:  base64.RawURLEncoding.EncodeToString(v1Body),
		Signature: base64.RawURLEncoding.EncodeToString(v1Signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	v1Envelope = append(v1Envelope, '\n')

	tests := map[string]func(string, []byte) ([]byte, int){
		"v1 downgrade": func(url string, body []byte) ([]byte, int) {
			if url == StablePairURL {
				return v1Envelope, http.StatusOK
			}
			return body, http.StatusOK
		},
		"bad root signature": func(url string, body []byte) ([]byte, int) {
			_, keysetSignatureURL := stableKeysetURLs(fixture.keyset.Epoch)
			if url == keysetSignatureURL {
				changed := append([]byte(nil), body...)
				changed[0] ^= 1
				return changed, http.StatusOK
			}
			return body, http.StatusOK
		},
		"bad manifest signature": func(url string, body []byte) ([]byte, int) {
			if url == StablePairURL {
				manifestBytes, signatureBytes, err := ParseCanonicalStablePair(body)
				if err != nil {
					t.Fatal(err)
				}
				signature, err := DecodeSignature(signatureBytes)
				if err != nil {
					t.Fatal(err)
				}
				signature[0] ^= 1
				changedSignature, err := EncodeSignature(signature)
				if err != nil {
					t.Fatal(err)
				}
				changed, err := EncodeCanonicalStablePair(manifestBytes, changedSignature)
				if err != nil {
					t.Fatal(err)
				}
				return changed, http.StatusOK
			}
			return body, http.StatusOK
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, _ := newDiscoveryClient(t, fixture, fixture.transport(mutate))
			if _, err := client.DiscoverStable(context.Background()); err == nil {
				t.Fatal("downgrade or invalid signature was accepted")
			}
		})
	}
}

func TestDiscoverStableUsesPersistedSequenceAfterRestart(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	statePath := StatePath(filepath.Join(t.TempDir(), "client"))
	first := NewStateStore(statePath)
	if err := first.Advance(fixture.manifest.Sequence); err != nil {
		t.Fatal(err)
	}

	restarted := NewStateStore(statePath)
	client := DiscoveryClient{
		RootKeyID:     fixture.keyset.RootKeyID,
		RootPublicKey: fixture.rootPublic,
		State:         restarted,
		Transport:     fixture.transport(nil),
		Now:           func() time.Time { return fixture.now },
	}
	if _, err := client.DiscoverStable(context.Background()); !errors.Is(err, ErrRollback) {
		t.Fatalf("restart rollback error = %v, want ErrRollback", err)
	}
	state, err := restarted.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != fixture.manifest.Sequence {
		t.Fatalf("restart sequence = %d", state.StableSequence)
	}
}

func TestDiscoverStableRejectsExpiredKeyset(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	client, _ := newDiscoveryClient(t, fixture, fixture.transport(nil))
	client.Now = func() time.Time { return fixture.now.Add(48 * time.Hour) }
	if _, err := client.DiscoverStable(context.Background()); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("expired keyset error = %v, want ErrInvalidKeyset", err)
	}
}

func TestDiscoverStableRejectsRedirectWithoutFollowing(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	requests := 0
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		resp := response(http.StatusFound, nil)
		resp.Header.Set("Location", "https://evil.example/manifest.json")
		resp.Request = req
		return resp, nil
	})
	client, _ := newDiscoveryClient(t, fixture, transport)
	if _, err := client.DiscoverStable(context.Background()); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("error = %v, want ErrDiscovery", err)
	}
	if requests != 1 {
		t.Fatalf("request count = %d, want 1", requests)
	}
}

func TestDiscoverStableRejectsBadHTTPAndOversizedBodies(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	tests := map[string]roundTripFunc{
		"status": func(*http.Request) (*http.Response, error) {
			return response(http.StatusServiceUnavailable, []byte("unavailable")), nil
		},
		"declared too large": func(*http.Request) (*http.Response, error) {
			resp := response(http.StatusOK, []byte("x"))
			resp.ContentLength = MaxKeysetBytes + 1
			return resp, nil
		},
		"streamed too large": func(*http.Request) (*http.Response, error) {
			body := make([]byte, MaxKeysetBytes+1)
			resp := response(http.StatusOK, body)
			resp.ContentLength = -1
			return resp, nil
		},
	}
	for name, transport := range tests {
		t.Run(name, func(t *testing.T) {
			client, _ := newDiscoveryClient(t, fixture, transport)
			if _, err := client.DiscoverStable(context.Background()); !errors.Is(err, ErrDiscovery) {
				t.Fatalf("error = %v, want ErrDiscovery", err)
			}
		})
	}
}

func TestDiscoverStablePreservesCancellationAndRejectsNegativeTimeout(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	client, _ := newDiscoveryClient(t, fixture, transport)
	if _, err := client.DiscoverStable(ctx); !errors.Is(err, ErrDiscovery) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}

	client.Transport = fixture.transport(nil)
	client.Timeout = -time.Second
	if _, err := client.DiscoverStable(context.Background()); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("negative timeout error = %v", err)
	}
}

func TestApplyStableRejectsUntrustedExpiredAndRevokedUpdates(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *discoveryFixture, *DiscoveryClient)
	}{
		{
			name: "untrusted manifest signature",
			mutate: func(t *testing.T, fixture *discoveryFixture, _ *DiscoveryClient) {
				t.Helper()
				manifestBytes, signatureBytes, err := ParseCanonicalStablePair(fixture.pairBody)
				if err != nil {
					t.Fatal(err)
				}
				signature, err := DecodeSignature(signatureBytes)
				if err != nil {
					t.Fatal(err)
				}
				signature[0] ^= 1
				encoded, err := EncodeSignature(signature)
				if err != nil {
					t.Fatal(err)
				}
				fixture.pairBody, err = EncodeCanonicalStablePair(manifestBytes, encoded)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "expired keyset",
			mutate: func(_ *testing.T, _ *discoveryFixture, client *DiscoveryClient) {
				client.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
			},
		},
		{
			name: "revoked signing key",
			mutate: func(t *testing.T, fixture *discoveryFixture, _ *DiscoveryClient) {
				t.Helper()
				fixture.keyset.Keys[0].Status = "revoked"
				fixture.keyset.Keys[0].RevokedAt = fixture.now.Add(-time.Minute).UTC().Format(time.RFC3339)
				keysetBody, err := EncodeCanonicalKeyset(fixture.keyset, fixture.now)
				if err != nil {
					t.Fatal(err)
				}
				fixture.keysetBody = keysetBody
				keysetSignature, err := EncodeSignature(ed25519.Sign(fixture.rootPrivate, keysetBody))
				if err != nil {
					t.Fatal(err)
				}
				fixture.keysetSignature = keysetSignature
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDiscoveryFixture(t)
			var err error
			packageManifest, archive := buildInstallerPackageFixture(t, nil)
			fixture.manifest.Version = packageManifest.Version
			fixture.manifest.ReleaseURL = packageManifest.ReleaseURL
			fixture.manifest.InstallerURL = packageManifest.InstallerURL
			fixture.manifest.InstallerSHA256 = sha256Hex(archive)
			fixture.manifestBody, err = EncodeCanonical(fixture.manifest)
			if err != nil {
				t.Fatal(err)
			}
			fixture.manifestSignature, err = EncodeSignature(ed25519.Sign(fixture.manifestPrivate, fixture.manifestBody))
			if err != nil {
				t.Fatal(err)
			}
			fixture.pairBody, err = EncodeCanonicalStablePair(fixture.manifestBody, fixture.manifestSignature)
			if err != nil {
				t.Fatal(err)
			}

			client, store := newDiscoveryClient(t, fixture, nil)
			test.mutate(t, &fixture, &client)
			client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == fixture.manifest.InstallerURL {
					return response(http.StatusOK, archive), nil
				}
				return fixture.transport(nil).RoundTrip(req)
			})

			calls := 0
			_, err = client.ApplyStable(
				context.Background(),
				InstallerClient{}, filepath.Join(t.TempDir(), "staging"), 0,
				func(context.Context, string) error { return nil },
				InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
					calls++
					return nil
				}),
			)
			if err == nil {
				t.Fatal("untrusted update reached successful installation")
			}
			if calls != 0 {
				t.Fatalf("installer executor calls = %d, want 0", calls)
			}
			state, loadErr := store.Load()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if state.StableSequence != 0 {
				t.Fatalf("rejected update advanced stable sequence to %d", state.StableSequence)
			}
		})
	}
}

func TestApplyStableReplayCannotInstallTwiceAfterRestart(t *testing.T) {
	fixture := newDiscoveryFixture(t)
	var err error
	packageManifest, archive := buildInstallerPackageFixture(t, nil)
	fixture.manifest.Version = packageManifest.Version
	fixture.manifest.ReleaseURL = packageManifest.ReleaseURL
	fixture.manifest.InstallerURL = packageManifest.InstallerURL
	fixture.manifest.InstallerSHA256 = sha256Hex(archive)
	fixture.manifestBody, err = EncodeCanonical(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.manifestSignature, err = EncodeSignature(ed25519.Sign(fixture.manifestPrivate, fixture.manifestBody))
	if err != nil {
		t.Fatal(err)
	}
	fixture.pairBody, err = EncodeCanonicalStablePair(fixture.manifestBody, fixture.manifestSignature)
	if err != nil {
		t.Fatal(err)
	}

	statePath := StatePath(filepath.Join(t.TempDir(), "client"))
	newClient := func() DiscoveryClient {
		store := NewStateStore(statePath)
		store.readInstalledVersion = func() (string, error) { return "v0.3.9", nil }
		return DiscoveryClient{
			RootKeyID: fixture.keyset.RootKeyID, RootPublicKey: fixture.rootPublic,
			State: store, Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == fixture.manifest.InstallerURL {
					return response(http.StatusOK, archive), nil
				}
				return fixture.transport(nil).RoundTrip(req)
			}),
			Now: func() time.Time { return fixture.now },
		}
	}
	calls := 0
	executor := InstallerExecutorFunc(func(context.Context, InstallTransaction, VerifiedInstallerPackage) error {
		calls++
		return nil
	})
	apply := func(client DiscoveryClient) error {
		_, applyErr := client.ApplyStable(
			context.Background(), InstallerClient{},
			filepath.Join(t.TempDir(), "staging"), 0,
			func(context.Context, string) error { return nil }, executor,
		)
		return applyErr
	}

	if err := apply(newClient()); err != nil {
		t.Fatalf("first verified update failed: %v", err)
	}
	if err := apply(newClient()); !errors.Is(err, ErrRollback) {
		t.Fatalf("replayed update error = %v, want ErrRollback", err)
	}
	if calls != 1 {
		t.Fatalf("installer executor calls = %d, want exactly 1", calls)
	}
	state, err := NewStateStore(statePath).Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.StableSequence != fixture.manifest.Sequence {
		t.Fatalf("persisted sequence = %d, want %d", state.StableSequence, fixture.manifest.Sequence)
	}
}

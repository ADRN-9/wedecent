package updateinfo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func signedDiscoveryFixture(t *testing.T) (ed25519.PublicKey, []byte, []byte, Manifest) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest()
	body, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeSignature(ed25519.Sign(privateKey, body))
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, body, signature, manifest
}

func response(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
	}
}

func TestDiscoverStableFetchesFixedSignedManifest(t *testing.T) {
	publicKey, body, signature, want := signedDiscoveryFixture(t)
	var mu sync.Mutex
	var requested []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		requested = append(requested, req.URL.String())
		mu.Unlock()
		switch req.URL.String() {
		case StableManifestURL:
			return response(http.StatusOK, body), nil
		case StableSignatureURL:
			return response(http.StatusOK, signature), nil
		default:
			t.Fatalf("unexpected URL %q", req.URL.String())
			return nil, errors.New("unexpected URL")
		}
	})

	got, err := (DiscoveryClient{PublicKey: publicKey, Transport: transport}).DiscoverStable(context.Background(), "v1.2.2", 41)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("DiscoverStable() = %#v, want %#v", got, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requested) != 2 || requested[0] != StableManifestURL || requested[1] != StableSignatureURL {
		t.Fatalf("requested URLs = %#v", requested)
	}
}

func TestDiscoverStableRejectsInvalidKeyBeforeNetwork(t *testing.T) {
	called := false
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("should not be called")
	})
	_, err := (DiscoveryClient{PublicKey: make([]byte, ed25519.PublicKeySize-1), Transport: transport}).DiscoverStable(context.Background(), "v1.0.0", 0)
	if !errors.Is(err, ErrDiscovery) {
		t.Fatalf("DiscoverStable() error = %v, want ErrDiscovery", err)
	}
	if called {
		t.Fatal("transport was called for an invalid pinned key")
	}
}

func TestDiscoverStableRejectsWrongSignatureAndRollback(t *testing.T) {
	publicKey, body, signature, manifest := signedDiscoveryFixture(t)
	badSignature := append([]byte(nil), signature...)
	badSignature[0] ^= 1

	for name, sig := range map[string][]byte{"signature": badSignature, "rollback": signature} {
		t.Run(name, func(t *testing.T) {
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == StableManifestURL {
					return response(http.StatusOK, body), nil
				}
				return response(http.StatusOK, sig), nil
			})
			sequence := uint64(41)
			if name == "rollback" {
				sequence = manifest.Sequence
			}
			_, err := (DiscoveryClient{PublicKey: publicKey, Transport: transport}).DiscoverStable(context.Background(), "v1.2.2", sequence)
			if name == "signature" && !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("DiscoverStable() error = %v, want ErrInvalidSignature", err)
			}
			if name == "rollback" && !errors.Is(err, ErrRollback) {
				t.Fatalf("DiscoverStable() error = %v, want ErrRollback", err)
			}
		})
	}
}

func TestDiscoverStableRejectsRedirectWithoutFollowing(t *testing.T) {
	publicKey, _, _, _ := signedDiscoveryFixture(t)
	var requests int
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Host != DownloadHost {
			t.Fatalf("redirect target was requested: %s", req.URL)
		}
		resp := response(http.StatusFound, nil)
		resp.Header.Set("Location", "https://evil.example/manifest.json")
		resp.Request = req
		return resp, nil
	})
	_, err := (DiscoveryClient{PublicKey: publicKey, Transport: transport}).DiscoverStable(context.Background(), "v1.0.0", 0)
	if !errors.Is(err, ErrDiscovery) {
		t.Fatalf("DiscoverStable() error = %v, want ErrDiscovery", err)
	}
	if requests != 1 {
		t.Fatalf("request count = %d, want 1", requests)
	}
}

func TestDiscoverStableRejectsBadHTTPAndOversizedBodies(t *testing.T) {
	publicKey, _, _, _ := signedDiscoveryFixture(t)
	tests := map[string]roundTripFunc{
		"status": func(*http.Request) (*http.Response, error) {
			return response(http.StatusServiceUnavailable, []byte("unavailable")), nil
		},
		"declared too large": func(*http.Request) (*http.Response, error) {
			resp := response(http.StatusOK, []byte("x"))
			resp.ContentLength = MaxManifestBytes + 1
			return resp, nil
		},
		"streamed too large": func(*http.Request) (*http.Response, error) {
			body := make([]byte, MaxManifestBytes+1)
			resp := response(http.StatusOK, body)
			resp.ContentLength = -1
			return resp, nil
		},
	}
	for name, transport := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := (DiscoveryClient{PublicKey: publicKey, Transport: transport}).DiscoverStable(context.Background(), "v1.0.0", 0)
			if !errors.Is(err, ErrDiscovery) {
				t.Fatalf("DiscoverStable() error = %v, want ErrDiscovery", err)
			}
		})
	}
}

func TestDiscoverStablePreservesCancellation(t *testing.T) {
	publicKey, _, _, _ := signedDiscoveryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	_, err := (DiscoveryClient{PublicKey: publicKey, Transport: transport}).DiscoverStable(ctx, "v1.0.0", 0)
	if !errors.Is(err, ErrDiscovery) || !errors.Is(err, context.Canceled) {
		t.Fatalf("DiscoverStable() error = %v, want ErrDiscovery + context.Canceled", err)
	}
}

func TestDiscoverStableRejectsNegativeTimeoutBeforeNetwork(t *testing.T) {
	publicKey, _, _, _ := signedDiscoveryFixture(t)
	called := false
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("should not be called")
	})
	_, err := (DiscoveryClient{PublicKey: publicKey, Transport: transport, Timeout: -time.Second}).DiscoverStable(context.Background(), "v1.0.0", 0)
	if !errors.Is(err, ErrDiscovery) {
		t.Fatalf("DiscoverStable() error = %v, want ErrDiscovery", err)
	}
	if called {
		t.Fatal("transport was called for an invalid timeout")
	}
}

package updateinfo

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	StableManifestURL     = "https://downloads.wedecent.com/windows/stable/manifest-v1.json"
	StableSignatureURL    = "https://downloads.wedecent.com/windows/stable/manifest-v1.sig"
	MaxSignatureFileBytes = 128
	DefaultFetchTimeout   = 10 * time.Second
)

var ErrDiscovery = errors.New("updateinfo: update discovery failed")

// DiscoveryClient fetches the stable update manifest from the fixed public
// origin and authenticates it with an explicitly provisioned Ed25519 key.
// Transport is injectable for tests; production callers should normally leave
// it nil so the default HTTPS transport is used.
type DiscoveryClient struct {
	PublicKey ed25519.PublicKey
	Transport http.RoundTripper
	Timeout   time.Duration
}

// DiscoverStable fetches and verifies the stable manifest, then applies the
// caller's installed-version and anti-rollback sequence policy. It never
// persists sequence state merely because a candidate was observed.
func (c DiscoveryClient) DiscoverStable(ctx context.Context, currentVersion string, highestSequence uint64) (Manifest, error) {
	var zero Manifest
	if len(c.PublicKey) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("%w: invalid pinned public key", ErrDiscovery)
	}
	if c.Timeout < 0 {
		return zero, fmt.Errorf("%w: timeout must not be negative", ErrDiscovery)
	}

	manifestBytes, err := c.fetch(ctx, StableManifestURL, MaxManifestBytes)
	if err != nil {
		return zero, err
	}
	signatureBytes, err := c.fetch(ctx, StableSignatureURL, MaxSignatureFileBytes)
	if err != nil {
		return zero, err
	}
	manifest, err := Verify(c.PublicKey, manifestBytes, signatureBytes)
	if err != nil {
		return zero, err
	}
	if err := CheckAdvance(currentVersion, highestSequence, manifest); err != nil {
		return zero, err
	}
	return manifest, nil
}

func (c DiscoveryClient) fetch(ctx context.Context, rawURL string, limit int) ([]byte, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultFetchTimeout
	}
	client := &http.Client{
		Transport: c.Transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("%w: redirects are not permitted", ErrDiscovery)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrDiscovery)
	}
	req.Header.Set("Accept", "application/json, text/plain;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch %s: %w", ErrDiscovery, rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: fetch %s returned HTTP %d", ErrDiscovery, rawURL, resp.StatusCode)
	}
	if resp.ContentLength > int64(limit) {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrDiscovery, limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrDiscovery, rawURL, err)
	}
	if len(body) == 0 || len(body) > limit {
		return nil, fmt.Errorf("%w: response size is invalid", ErrDiscovery)
	}
	return body, nil
}

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
	StableKeysetURLPrefix = "https://downloads.wedecent.com/windows/stable/keysets/"
	StableManifestURL     = "https://downloads.wedecent.com/windows/stable/manifest-v2.json"
	StableSignatureURL    = "https://downloads.wedecent.com/windows/stable/manifest-v2.sig"
	MaxSignatureFileBytes = 128
	DefaultFetchTimeout   = 10 * time.Second
)

var ErrDiscovery = errors.New("updateinfo: update discovery failed")

// DiscoveryClient requires an independently provisioned root public key and
// protected state store. There is deliberately no manifest-v1 fallback.
type DiscoveryClient struct {
	RootKeyID     string
	RootPublicKey ed25519.PublicKey
	State         *StateStore
	Transport     http.RoundTripper
	Timeout       time.Duration
	Now           func() time.Time
}

// DiscoverStable verifies and persists the root-authorized keyset before
// verifying a v2 manifest. Sequence rollback is checked against both caller
// state and the protected persisted sequence, which is committed after install.
func (c DiscoveryClient) DiscoverStable(ctx context.Context, currentVersion string, highestSequence uint64) (Manifest, error) {
	var zero Manifest
	if ctx == nil || c.State == nil || c.State.Path == "" ||
		len(c.RootPublicKey) != ed25519.PublicKeySize || !keyIDPattern.MatchString(c.RootKeyID) {
		return zero, fmt.Errorf("%w: pinned root key and protected state store are required", ErrDiscovery)
	}
	if c.Timeout < 0 {
		return zero, fmt.Errorf("%w: timeout must not be negative", ErrDiscovery)
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}

	manifestBytes, err := c.fetch(ctx, StableManifestURL, MaxManifestBytes)
	if err != nil {
		return zero, err
	}
	signatureBytes, err := c.fetch(ctx, StableSignatureURL, MaxSignatureFileBytes)
	if err != nil {
		return zero, err
	}
	untrustedManifest, err := ParseCanonical(manifestBytes)
	if err != nil || untrustedManifest.Schema != ManifestSchemaV2 {
		return zero, fmt.Errorf("%w: stable channel requires a canonical schema-v2 manifest", ErrDiscovery)
	}
	keysetURL, keysetSignatureURL := stableKeysetURLs(untrustedManifest.KeysetEpoch)
	keysetBytes, err := c.fetch(ctx, keysetURL, MaxKeysetBytes)
	if err != nil {
		return zero, err
	}
	keysetSignature, err := c.fetch(ctx, keysetSignatureURL, MaxSignatureFileBytes)
	if err != nil {
		return zero, err
	}
	verified, err := c.State.VerifyAndAdvanceKeyset(ctx, c.RootKeyID, c.RootPublicKey, keysetBytes, keysetSignature, now)
	if err != nil {
		return zero, fmt.Errorf("%w: verify keyset: %w", ErrDiscovery, err)
	}
	persisted, err := c.State.Load()
	if err != nil {
		return zero, fmt.Errorf("%w: load protected update state: %w", ErrDiscovery, err)
	}
	if persisted.KeysetEpoch != verified.Epoch() || persisted.KeysetDigest != verified.Digest() {
		return zero, fmt.Errorf("%w: verified keyset does not match persisted trust state", ErrDiscovery)
	}
	if persisted.StableSequence > highestSequence {
		highestSequence = persisted.StableSequence
	}

	manifest, err := VerifyManifestV2(verified, manifestBytes, signatureBytes, now, currentVersion, highestSequence)
	if err != nil {
		return zero, fmt.Errorf("%w: verify v2 manifest: %w", ErrDiscovery, err)
	}
	return manifest, nil
}

func stableKeysetURLs(epoch uint64) (string, string) {
	base := fmt.Sprintf("%s%d/", StableKeysetURLPrefix, epoch)
	return base + "keyset.json", base + "keyset.sig"
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

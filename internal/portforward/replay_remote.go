package portforward

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
)

const (
	remoteReplayTimeout     = 8 * time.Second
	remoteReplayResponseMax = 8 << 10
	remoteReplayDomain      = "wedecent-port-forward-replay-consume-v1"
)

// RemoteReplay delegates single-use state to the independent control-plane
// ledger. The service account cannot delete or reset that ledger.
type RemoteReplay struct {
	Endpoint string
	APIKey   string
	DeviceID mesh.DeviceID
	Signer   crypto.Signer
	Client   *http.Client
	Now      func() time.Time
}

type remoteReplayRequest struct {
	DeviceID            string        `json:"device_id"`
	Authorization       Authorization `json:"authorization"`
	AuthorizationSHA256 string        `json:"authorization_sha256"`
	DeviceSignature     string        `json:"device_signature"`
}

type remoteReplayResponse struct {
	Accepted   bool   `json:"accepted"`
	Generation string `json:"generation"`
	StateHash  string `json:"state_hash"`
}

// NewRemoteReplay requires the exact Supabase Edge Function endpoint and a
// public Data API key. The key is not a secret; device and capability
// signatures are the authorization boundary.
func NewRemoteReplay(endpoint, apiKey string, deviceID mesh.DeviceID, signer crypto.Signer) (*RemoteReplay, error) {
	endpoint = strings.TrimSpace(endpoint)
	apiKey = strings.TrimSpace(apiKey)
	if !deviceIDPattern.MatchString(string(deviceID)) || signer == nil {
		return nil, ErrReplayUnavailable
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize || identity.DeviceID(publicKey) != string(deviceID) {
		return nil, ErrReplayUnavailable
	}
	if apiKey == "" || len(apiKey) > 4096 || strings.ContainsAny(apiKey, "\r\n\t ") {
		return nil, ErrReplayUnavailable
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "/functions/v1/port-forward-replay" || parsed.Hostname() == "" {
		return nil, ErrReplayUnavailable
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, ErrReplayUnavailable
		}
	default:
		return nil, ErrReplayUnavailable
	}
	return &RemoteReplay{
		Endpoint: endpoint,
		APIKey:   apiKey,
		DeviceID: deviceID,
		Signer:   signer,
		Client: &http.Client{
			Timeout: remoteReplayTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// ConsumePortForwardAuthorization deliberately fails: a remote authority must
// receive the already-verified complete capability, never a bare caller JTI.
func (r *RemoteReplay) ConsumePortForwardAuthorization(context.Context, string, time.Time) error {
	return ErrReplayUnavailable
}

func (r *RemoteReplay) ConsumeVerifiedPortForwardAuthorization(ctx context.Context, authorization Authorization) error {
	if ctx == nil || r == nil || r.Signer == nil || r.Client == nil {
		return ErrReplayUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	claims := authorization.Claims
	if err := ValidateClaims(claims); err != nil {
		return ErrAuthorizationInvalid
	}
	if r.DeviceID != claims.InitiatingDevice && r.DeviceID != claims.DestinationDevice {
		return ErrAuthorizationMismatch
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	if claims.IssuedAtUnixMS > now.UnixMilli() {
		return ErrAuthorizationNotYetValid
	}
	if claims.ExpiresAtUnixMS <= now.UnixMilli() {
		return ErrAuthorizationExpired
	}
	message, err := canonicalMessage(authorization.KeyID, claims)
	if err != nil {
		return ErrAuthorizationInvalid
	}
	capabilitySignature, err := base64.RawURLEncoding.Strict().DecodeString(authorization.Signature)
	if err != nil || len(capabilitySignature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(capabilitySignature) != authorization.Signature {
		return ErrAuthorizationSignature
	}
	digestInput := make([]byte, 0, len(message)+len(capabilitySignature))
	digestInput = append(digestInput, message...)
	digestInput = append(digestInput, capabilitySignature...)
	authorizationDigest := sha256.Sum256(digestInput)
	deviceMessage := remoteReplayDeviceMessage(r.DeviceID, claims.JTI, claims.ExpiresAtUnixMS, authorizationDigest)
	deviceSignature, err := r.Signer.Sign(rand.Reader, deviceMessage, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("%w: device replay proof signing failed", ErrReplayUnavailable)
	}
	publicKey, ok := r.Signer.Public().(ed25519.PublicKey)
	if !ok || len(deviceSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, deviceMessage, deviceSignature) {
		return fmt.Errorf("%w: device replay proof signer mismatch", ErrReplayUnavailable)
	}
	payload, err := json.Marshal(remoteReplayRequest{
		DeviceID:            string(r.DeviceID),
		Authorization:       cloneAuthorization(authorization),
		AuthorizationSHA256: hex.EncodeToString(authorizationDigest[:]),
		DeviceSignature:     base64.RawURLEncoding.EncodeToString(deviceSignature),
	})
	if err != nil {
		return ErrReplayUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return ErrReplayUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("apikey", r.APIKey)
	client := *r.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout <= 0 {
		client.Timeout = remoteReplayTimeout
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: remote replay authority request failed: %v", ErrReplayUnavailable, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, remoteReplayResponseMax+1))
	if err != nil || len(body) > remoteReplayResponseMax {
		return ErrReplayUnavailable
	}
	if response.StatusCode == http.StatusConflict {
		return ErrAuthorizationReplay
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: remote replay authority returned HTTP %d", ErrReplayUnavailable, response.StatusCode)
	}
	var result remoteReplayResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return ErrReplayUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrReplayUnavailable
	}
	if !result.Accepted {
		return ErrAuthorizationReplay
	}
	generation, err := strconv.ParseUint(result.Generation, 10, 64)
	if err != nil || generation == 0 || len(result.StateHash) != sha256.Size*2 {
		return ErrReplayUnavailable
	}
	if _, err := hex.DecodeString(result.StateHash); err != nil || strings.ToLower(result.StateHash) != result.StateHash {
		return ErrReplayUnavailable
	}
	return nil
}

func remoteReplayDeviceMessage(deviceID mesh.DeviceID, jti string, expiresAtUnixMS int64, authorizationDigest [32]byte) []byte {
	return []byte(remoteReplayDomain + "\n" +
		"device_id=" + string(deviceID) + "\n" +
		"jti=" + jti + "\n" +
		"expires_at_unix_ms=" + strconv.FormatInt(expiresAtUnixMS, 10) + "\n" +
		"authorization_sha256=" + hex.EncodeToString(authorizationDigest[:]) + "\n")
}

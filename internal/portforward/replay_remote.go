package portforward

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
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
	endpoint string
	apiKey   string
	deviceID mesh.DeviceID
	signer   crypto.Signer
	client   *http.Client
	now      func() time.Time
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

// replayAuthorityHostname and replayAuthoritySPKISHA256 are release trust anchors.
// Set them with Go linker -X flags; service configuration cannot change them.
var (
	replayAuthorityHostname   string
	replayAuthoritySPKISHA256 string
)

const remoteReplayFunctionPath = "/functions/v1/port-forward-replay"

// NewRemoteReplay is an unpinned constructor for isolated tests and development.
// Production callers must use NewProductionRemoteReplay.
func NewRemoteReplay(endpoint, apiKey string, deviceID mesh.DeviceID, signer crypto.Signer) (*RemoteReplay, error) {
	return newRemoteReplay(endpoint, apiKey, "", 0, nil, deviceID, signer)
}

// NewProductionRemoteReplay uses hostname and SPKI pins embedded in the binary.
// The endpoint URL may select no authority other than that independently trusted
// host on port 443 and the fixed replay function path.
func NewProductionRemoteReplay(endpoint, apiKey string, deviceID mesh.DeviceID, signer crypto.Signer) (*RemoteReplay, error) {
	hostname := strings.TrimSpace(replayAuthorityHostname)
	pins := strings.TrimSpace(replayAuthoritySPKISHA256)
	if hostname == "" || pins == "" {
		return nil, fmt.Errorf("%w: replay authority hostname and SPKI pins are not embedded in this build", ErrReplayUnavailable)
	}
	return NewPinnedRemoteReplay(endpoint, apiKey, hostname, 443, pins, deviceID, signer)
}

// NewPinnedRemoteReplay binds the endpoint to an independently trusted hostname,
// port, and one or more SHA-256 hashes of the TLS leaf certificate SPKI.
func NewPinnedRemoteReplay(endpoint, apiKey, trustedHostname string, trustedPort uint16, spkiPins string, deviceID mesh.DeviceID, signer crypto.Signer) (*RemoteReplay, error) {
	if strings.TrimSpace(trustedHostname) != trustedHostname ||
		!validReplayAuthorityHostname(trustedHostname) || trustedPort == 0 {
		return nil, ErrReplayUnavailable
	}
	pins, err := parseReplaySPKIPins(spkiPins)
	if err != nil {
		return nil, err
	}
	return newRemoteReplay(endpoint, apiKey, trustedHostname, trustedPort, pins, deviceID, signer)
}

func newRemoteReplay(endpoint, apiKey, trustedHostname string, trustedPort uint16, spkiPins [][sha256.Size]byte, deviceID mesh.DeviceID, signer crypto.Signer) (*RemoteReplay, error) {
	endpoint = strings.TrimSpace(endpoint)
	apiKey = strings.TrimSpace(apiKey)
	if !deviceIDPattern.MatchString(string(deviceID)) || signer == nil {
		return nil, ErrReplayUnavailable
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize || identity.DeviceID(publicKey) != string(deviceID) {
		return nil, ErrReplayUnavailable
	}
	if !validPublicReplayAPIKey(apiKey) {
		return nil, fmt.Errorf("%w: only a public Supabase Data API key may be used; service-role keys are forbidden", ErrReplayUnavailable)
	}
	parsed, err := validateRemoteReplayEndpoint(endpoint, trustedHostname, trustedPort)
	if err != nil {
		return nil, err
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, ErrReplayUnavailable
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: parsed.Hostname(),
	}
	if len(spkiPins) > 0 {
		pins := append([][sha256.Size]byte(nil), spkiPins...)
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("%w: replay authority supplied no peer certificate", ErrReplayUnavailable)
			}
			actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			for _, expected := range pins {
				if subtle.ConstantTimeCompare(actual[:], expected[:]) == 1 {
					return nil
				}
			}
			return fmt.Errorf("%w: replay authority SPKI pin mismatch", ErrReplayUnavailable)
		}
	}
	transport := defaultTransport.Clone()
	transport.TLSClientConfig = tlsConfig
	return &RemoteReplay{
		endpoint: endpoint,
		apiKey:   apiKey,
		deviceID: deviceID,
		signer:   signer,
		client: &http.Client{
			Transport: transport,
			Timeout:   remoteReplayTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func validateRemoteReplayEndpoint(endpoint, trustedHostname string, trustedPort uint16) (*url.URL, error) {
	if endpoint == "" || strings.TrimSpace(endpoint) != endpoint {
		return nil, ErrReplayUnavailable
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Opaque != "" || parsed.Path != remoteReplayFunctionPath ||
		parsed.RawPath != "" || parsed.Hostname() == "" || strings.HasSuffix(parsed.Host, ":") {
		return nil, ErrReplayUnavailable
	}
	hostname := parsed.Hostname()
	if !validReplayAuthorityHostname(hostname) {
		return nil, ErrReplayUnavailable
	}
	port := uint64(443)
	if rawPort := parsed.Port(); rawPort != "" {
		port, err = strconv.ParseUint(rawPort, 10, 16)
		if err != nil || port == 0 || strconv.FormatUint(port, 10) != rawPort {
			return nil, ErrReplayUnavailable
		}
	}
	if trustedHostname != "" && (hostname != trustedHostname || uint16(port) != trustedPort) {
		return nil, fmt.Errorf("%w: replay endpoint does not match the embedded authority hostname and port", ErrReplayUnavailable)
	}
	if trustedHostname == "" && trustedPort != 0 {
		return nil, ErrReplayUnavailable
	}
	return parsed, nil
}

func validReplayAuthorityHostname(hostname string) bool {
	if hostname == "" || strings.TrimSpace(hostname) != hostname ||
		strings.ToLower(hostname) != hostname || strings.HasSuffix(hostname, ".") {
		return false
	}
	if net.ParseIP(hostname) != nil {
		return true
	}
	if len(hostname) > 253 {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func parseReplaySPKIPins(raw string) ([][sha256.Size]byte, error) {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	if len(parts) == 0 || len(parts) > 4 {
		return nil, ErrReplayUnavailable
	}
	pins := make([][sha256.Size]byte, 0, len(parts))
	seen := make(map[[sha256.Size]byte]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) != sha256.Size*2 {
			return nil, ErrReplayUnavailable
		}
		decoded, err := hex.DecodeString(part)
		if err != nil || len(decoded) != sha256.Size {
			return nil, ErrReplayUnavailable
		}
		var pin [sha256.Size]byte
		copy(pin[:], decoded)
		if _, exists := seen[pin]; exists {
			return nil, ErrReplayUnavailable
		}
		seen[pin] = struct{}{}
		pins = append(pins, pin)
	}
	return pins, nil
}

func validPublicReplayAPIKey(apiKey string) bool {
	if apiKey == "" || len(apiKey) > 4096 || strings.ContainsAny(apiKey, "\r\n\t ") ||
		strings.HasPrefix(strings.ToLower(apiKey), "sb_secret_") {
		return false
	}
	parts := strings.Split(apiKey, ".")
	if len(parts) == 3 {
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil {
			var claims struct {
				Role string `json:"role"`
			}
			if json.Unmarshal(payload, &claims) == nil && claims.Role != "" && claims.Role != "anon" && claims.Role != "authenticated" {
				return false
			}
		}
	}
	return true
}

// ConsumePortForwardAuthorization deliberately fails: a remote authority must
// receive the already-verified complete capability, never a bare caller JTI.
func (r *RemoteReplay) ConsumePortForwardAuthorization(context.Context, string, time.Time) error {
	return ErrReplayUnavailable
}

func (r *RemoteReplay) ConsumeVerifiedPortForwardAuthorization(ctx context.Context, authorization Authorization) error {
	if ctx == nil || r == nil || r.signer == nil || r.client == nil {
		return ErrReplayUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	claims := authorization.Claims
	if err := ValidateClaims(claims); err != nil {
		return ErrAuthorizationInvalid
	}
	if r.deviceID != claims.InitiatingDevice && r.deviceID != claims.DestinationDevice {
		return ErrAuthorizationMismatch
	}
	now := time.Now().UTC()
	if r.now != nil {
		now = r.now().UTC()
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
	deviceMessage := remoteReplayDeviceMessage(r.deviceID, claims.JTI, claims.ExpiresAtUnixMS, authorizationDigest)
	deviceSignature, err := r.signer.Sign(rand.Reader, deviceMessage, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("%w: device replay proof signing failed", ErrReplayUnavailable)
	}
	publicKey, ok := r.signer.Public().(ed25519.PublicKey)
	if !ok || len(deviceSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, deviceMessage, deviceSignature) {
		return fmt.Errorf("%w: device replay proof signer mismatch", ErrReplayUnavailable)
	}
	payload, err := json.Marshal(remoteReplayRequest{
		DeviceID:            string(r.deviceID),
		Authorization:       cloneAuthorization(authorization),
		AuthorizationSHA256: hex.EncodeToString(authorizationDigest[:]),
		DeviceSignature:     base64.RawURLEncoding.EncodeToString(deviceSignature),
	})
	if err != nil {
		return ErrReplayUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return ErrReplayUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("apikey", r.apiKey)
	client := *r.client
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

package agentadmission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
)

const (
	proofAudience = "wedecent-agent-admission"
	proofPurpose  = "relay.agent.admission.acquire"
	agentAudience = "wedecent-relay-agent"
	agentPurpose  = "relay.agent.connect"
	proofLifetime = 30 * time.Second
	maxBodyBytes  = 2048
	maxReplyBytes = 16 << 10
)

var deviceIDPattern = regexp.MustCompile("^wd_[a-z2-7]{16}$")
var fingerprintPattern = regexp.MustCompile("^SHA256:[A-F0-9]{64}$")
var uuidPattern = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

type Client struct {
	SupabaseURL    string
	PublishableKey string
	HTTP           *http.Client
	Now            func() time.Time
}

type admissionRequest struct {
	DeviceID string `json:"device_id"`
	Slot     int    `json:"slot"`
	Proof    string `json:"proof"`
}

type admissionResponse struct {
	AgentAdmission string `json:"agent_admission"`
}

type proofHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type proofClaims struct {
	Issuer                 string `json:"iss"`
	Subject                string `json:"sub"`
	Audience               string `json:"aud"`
	Purpose                string `json:"purpose"`
	DeviceID               string `json:"device_id"`
	PublicKeyFingerprint   string `json:"public_key_fingerprint"`
	Slot                   int    `json:"slot"`
	IssuedAt               int64  `json:"iat"`
	ExpiresAt              int64  `json:"exp"`
	TokenID                string `json:"jti"`
}

type capabilityClaims struct {
	Issuer               string `json:"iss"`
	Subject              string `json:"sub"`
	Audience             string `json:"aud"`
	Purpose              string `json:"purpose"`
	DeviceID             string `json:"device_id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Slot                 int    `json:"slot"`
	TokenID              string `json:"jti"`
	IssuedAt             int64  `json:"iat"`
	ExpiresAt            int64  `json:"exp"`
}

func (c Client) Validate() error {
	if strings.TrimSpace(c.PublishableKey) == "" || strings.ContainsAny(c.PublishableKey, "
	 ") || len(c.PublishableKey) > 4096 {
		return errors.New("agent admission publishable key is missing or invalid")
	}
	_, err := c.endpoint()
	return err
}

func (c Client) Acquire(ctx context.Context, id *identity.Identity, slot int) (string, error) {
	if id == nil || len(id.PublicKey) != ed25519.PublicKeySize || len(id.PrivateKey) != ed25519.PrivateKeySize {
		return "", errors.New("agent admission identity is incomplete")
	}
	if !deviceIDPattern.MatchString(id.ID) || identity.DeviceID(id.PublicKey) != id.ID {
		return "", errors.New("agent admission identity does not match its public key")
	}
	if !id.PrivateKey.Public().(ed25519.PublicKey).Equal(id.PublicKey) {
		return "", errors.New("agent admission signer does not match its public key")
	}
	if slot < 1 || slot > 32 {
		return "", errors.New("agent admission slot must be between 1 and 32")
	}
	endpoint, err := c.endpoint()
	if err != nil {
		return "", err
	}
	if err := c.Validate(); err != nil {
		return "", err
	}

	fingerprint, err := identity.FingerprintPublicKey(id.PublicKey)
	if err != nil || !fingerprintPattern.MatchString(fingerprint) {
		return "", errors.New("could not fingerprint agent identity")
	}
	now := c.now().UTC().Truncate(time.Second)
	proof, err := makeProof(id, fingerprint, slot, now)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(admissionRequest{DeviceID: id.ID, Slot: slot, Proof: proof})
	if err != nil {
		return "", fmt.Errorf("encode agent admission request: %w", err)
	}
	if len(body) > maxBodyBytes {
		return "", errors.New("agent admission request exceeds size limit")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build agent admission request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("apikey", strings.TrimSpace(c.PublishableKey))

	client := c.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request agent admission: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("agent admission service rejected request: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes+1))
	if err != nil {
		return "", fmt.Errorf("read agent admission response: %w", err)
	}
	if len(data) == 0 || len(data) > maxReplyBytes {
		return "", errors.New("agent admission response has an invalid size")
	}
	var reply admissionResponse
	if err := json.Unmarshal(data, &reply); err != nil {
		return "", errors.New("agent admission service returned malformed JSON")
	}
	token := strings.TrimSpace(reply.AgentAdmission)
	if err := validateCapability(token, id.ID, fingerprint, slot, now); err != nil {
		return "", fmt.Errorf("agent admission service returned an invalid capability: %w", err)
	}
	return token, nil
}

func makeProof(id *identity.Identity, fingerprint string, slot int, now time.Time) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate agent admission proof nonce: %w", err)
	}
	header, err := json.Marshal(proofHeader{Algorithm: "EdDSA", Type: "JWT", KeyID: fingerprint})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(proofClaims{
		Issuer: id.ID, Subject: id.ID, Audience: proofAudience, Purpose: proofPurpose,
		DeviceID: id.ID, PublicKeyFingerprint: fingerprint, Slot: slot,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(proofLifetime).Unix(),
		TokenID: base64.RawURLEncoding.EncodeToString(nonce),
	})
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature := ed25519.Sign(id.PrivateKey, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func validateCapability(token, deviceID, fingerprint string, slot int, now time.Time) error {
	if len(token) < 32 || len(token) > 8192 || strings.ContainsAny(token, "
	 ") {
		return errors.New("invalid token length or whitespace")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}
	var header proofHeader
	if err := decodePart(parts[0], &header); err != nil {
		return errors.New("invalid token header")
	}
	if header.Algorithm != "EdDSA" || header.Type != "JWT" || header.KeyID == "" {
		return errors.New("unsupported token header")
	}
	var claims capabilityClaims
	if err := decodePart(parts[1], &claims); err != nil {
		return errors.New("invalid token claims")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid token signature encoding")
	}
	if claims.Issuer != "wedecent-control-plane" || claims.Audience != agentAudience ||
		claims.Subject != deviceID || claims.DeviceID != deviceID ||
		claims.PublicKeyFingerprint != fingerprint || claims.Purpose != agentPurpose ||
		claims.Slot != slot || !uuidPattern.MatchString(claims.TokenID) {
		return errors.New("capability scope mismatch")
	}
	nowUnix := now.Unix()
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > 120 ||
		claims.IssuedAt > nowUnix+30 || claims.ExpiresAt <= nowUnix {
		return errors.New("capability is expired or has an invalid lifetime")
	}
	return nil
}

func decodePart(part string, out any) error {
	if part == "" || len(part) > 4096 {
		return errors.New("invalid JWT part")
	}
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil || len(data) == 0 {
		return errors.New("invalid JWT part encoding")
	}
	return json.Unmarshal(data, out)
}

func (c Client) endpoint() (string, error) {
	raw := strings.TrimSpace(c.SupabaseURL)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return "", errors.New("agent admission Supabase URL must be an absolute origin")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname())) {
		return "", errors.New("agent admission Supabase URL must use HTTPS")
	}
	u.Path = "/functions/v1/agent-admission"
	u.RawPath = ""
	return u.String(), nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c Client) httpClient() *http.Client {
	client := &http.Client{Timeout: 10 * time.Second}
	if c.HTTP != nil {
		copy := *c.HTTP
		client = &copy
		if client.Timeout <= 0 {
			client.Timeout = 10 * time.Second
		}
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if standard, ok := transport.(*http.Transport); ok {
		clone := standard.Clone()
		tlsConfig := clone.TLSClientConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.MinVersion = tls.VersionTLS13
		clone.TLSClientConfig = tlsConfig
		client.Transport = clone
	}
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

func (c Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

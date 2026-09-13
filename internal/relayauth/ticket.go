package relayauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
)

const (
	TicketPrefix        = "wdt2"
	TicketAudience      = "wedecent-relay"
	TicketTTL           = 90 * time.Second
	signingContext      = "wedecent-relay-ticket-v2\n"
	maxAgentSlots       = 32
	relayTimeTimeout    = 5 * time.Second
	maxRelayClockOffset = 24 * time.Hour
	maxRelayTimeBody    = 1024
)

type Claims struct {
	Version   int    `json:"v"`
	Audience  string `json:"aud"`
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Role      string `json:"role"`
	Slot      int    `json:"slot,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	TokenID   string `json:"jti"`
	PublicKey string `json:"pk"`
}

// TicketSource returns fresh, short-lived proof-of-possession relay tickets.
// relayBaseURL identifies the authenticated relay whose clock scopes the ticket.
// The identity private key never leaves the local machine.
type TicketSource func(ctx context.Context, relayBaseURL, targetDeviceID, role string, slot int) (string, error)

func NewTicketSource(id *identity.Identity) TicketSource {
	return func(ctx context.Context, relayBaseURL, targetDeviceID, role string, slot int) (string, error) {
		now, err := relayNow(ctx, relayBaseURL)
		if err != nil {
			return "", fmt.Errorf("synchronize relay time: %w", err)
		}
		return Issue(id, targetDeviceID, role, slot, now)
	}
}

func Issue(id *identity.Identity, targetDeviceID, role string, slot int, now time.Time) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate relay ticket nonce: %w", err)
	}
	return issue(id, targetDeviceID, role, slot, now, nonce)
}

func issue(id *identity.Identity, targetDeviceID, role string, slot int, now time.Time, nonce []byte) (string, error) {
	if id == nil || len(id.PublicKey) != ed25519.PublicKeySize || len(id.PrivateKey) != ed25519.PrivateKeySize {
		return "", errors.New("relay ticket identity is incomplete")
	}
	if identity.DeviceID(id.PublicKey) != id.ID {
		return "", errors.New("relay ticket identity ID does not match public key")
	}
	if !validDeviceID(targetDeviceID) {
		return "", errors.New("invalid relay ticket target device ID")
	}
	switch role {
	case "agent":
		if targetDeviceID != id.ID {
			return "", errors.New("agent relay ticket must target its own device ID")
		}
		if slot < 1 || slot > maxAgentSlots {
			return "", errors.New("agent relay ticket slot must be between 1 and 32")
		}
	case "client":
		if slot != 0 {
			return "", errors.New("client relay ticket must not contain an agent slot")
		}
	case "authorize":
		if targetDeviceID != id.ID {
			return "", errors.New("authorization ticket must target its own device ID")
		}
		if slot != 0 {
			return "", errors.New("authorization ticket must not contain an agent slot")
		}
	default:
		return "", errors.New("invalid relay ticket role")
	}
	if len(nonce) != 16 {
		return "", errors.New("relay ticket nonce must contain 16 bytes")
	}

	now = now.UTC().Truncate(time.Second)
	claims := Claims{
		Version:   2,
		Audience:  TicketAudience,
		Issuer:    id.ID,
		Subject:   targetDeviceID,
		Role:      role,
		Slot:      slot,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(TicketTTL).Unix(),
		TokenID:   base64.RawURLEncoding.EncodeToString(nonce),
		PublicKey: base64.RawURLEncoding.EncodeToString(id.PublicKey),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode relay ticket: %w", err)
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	message := []byte(signingContext + payloadPart)
	signature := ed25519.Sign(id.PrivateKey, message)
	return TicketPrefix + "." + payloadPart + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type relayTimeResponse struct {
	UnixMillis int64 `json:"unix_ms"`
}

func relayNow(ctx context.Context, relayBaseURL string) (time.Time, error) {
	timeURL, err := relayTimeURL(relayBaseURL)
	if err != nil {
		return time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, timeURL, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("build relay time request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")

	client := &http.Client{
		Timeout: relayTimeTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	started := time.Now()
	resp, err := client.Do(req)
	finished := time.Now()
	if err != nil {
		return time.Time{}, fmt.Errorf("fetch relay time: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRelayTimeBody))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return time.Time{}, fmt.Errorf("relay time endpoint rejected request: %s", msg)
	}

	limited := io.LimitReader(resp.Body, maxRelayTimeBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return time.Time{}, fmt.Errorf("read relay time response: %w", err)
	}
	if len(body) == 0 || len(body) > maxRelayTimeBody {
		return time.Time{}, errors.New("invalid relay time response length")
	}
	var payload relayTimeResponse
	if err := json.Unmarshal(body, &payload); err != nil || payload.UnixMillis <= 0 {
		return time.Time{}, errors.New("invalid relay time response")
	}

	roundTrip := finished.Sub(started)
	if roundTrip < 0 || roundTrip > relayTimeTimeout {
		return time.Time{}, errors.New("relay time request exceeded acceptable round-trip time")
	}
	serverTime := time.UnixMilli(payload.UnixMillis).UTC()
	localMidpoint := started.Add(roundTrip / 2)
	offset := serverTime.Sub(localMidpoint)
	if offset > maxRelayClockOffset || offset < -maxRelayClockOffset {
		return time.Time{}, fmt.Errorf("relay clock offset %s exceeds 24h safety bound", offset.Round(time.Second))
	}
	return finished.Add(offset).UTC(), nil
}

func relayTimeURL(relayBaseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(relayBaseURL))
	if err != nil || u.Host == "" {
		return "", errors.New("relay time source must be a valid URL")
	}
	switch u.Scheme {
	case "https":
	case "wss":
		u.Scheme = "https"
	case "http":
	case "ws":
		u.Scheme = "http"
	default:
		return "", errors.New("relay time source must use https, http, wss, or ws")
	}
	u.User = nil
	u.Path = "/v1/time"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func validDeviceID(s string) bool {
	if len(s) != 19 || !strings.HasPrefix(s, "wd_") {
		return false
	}
	for _, r := range s[3:] {
		if (r < 'a' || r > 'z') && (r < '2' || r > '7') {
			return false
		}
	}
	return true
}

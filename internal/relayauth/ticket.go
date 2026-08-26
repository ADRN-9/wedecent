package relayauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
)

const (
	TicketPrefix   = "wdt2"
	TicketAudience = "wedecent-relay"
	TicketTTL      = 90 * time.Second
	signingContext = "wedecent-relay-ticket-v2\n"
	maxAgentSlots  = 32
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
// The identity private key never leaves the local machine.
type TicketSource func(targetDeviceID, role string, slot int) (string, error)

func NewTicketSource(id *identity.Identity) TicketSource {
	return func(targetDeviceID, role string, slot int) (string, error) {
		return Issue(id, targetDeviceID, role, slot, time.Now().UTC())
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

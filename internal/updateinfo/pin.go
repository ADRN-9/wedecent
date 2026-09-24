package updateinfo

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrPublicKeyUnprovisioned means this binary was built without a stable update
// verification key. Update discovery must remain disabled in that state.
var ErrPublicKeyUnprovisioned = errors.New("updateinfo: update public key is not provisioned")

// provisionedPublicKeyText is intentionally set only at link time by the
// release build. There is no runtime file/environment fallback: changing the
// stable update trust anchor requires a new authenticated client build.
var provisionedPublicKeyText string

func ProvisionedPublicKey() (ed25519.PublicKey, error) {
	if provisionedPublicKeyText == "" {
		return nil, ErrPublicKeyUnprovisioned
	}
	key, err := DecodePublicKey([]byte(provisionedPublicKeyText))
	if err != nil {
		return nil, fmt.Errorf("updateinfo: invalid provisioned update public key: %w", err)
	}
	return key, nil
}

func PublicKeyFingerprint(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: public key length", ErrInvalidSignature)
	}
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:]), nil
}

func ProvisionedPublicKeyFingerprint() (string, error) {
	publicKey, err := ProvisionedPublicKey()
	if err != nil {
		return "", err
	}
	return PublicKeyFingerprint(publicKey)
}

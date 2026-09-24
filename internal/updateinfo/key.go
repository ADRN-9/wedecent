package updateinfo

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// EncodePublicKey returns the canonical text representation used by update
// release tooling. Public keys are non-secret, but callers must still obtain
// the production pin from an authenticated provisioning path rather than the
// download origin or trust-on-first-use.
func EncodePublicKey(publicKey ed25519.PublicKey) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key length", ErrInvalidSignature)
	}
	encoded := base64.RawURLEncoding.EncodeToString(publicKey)
	return append([]byte(encoded), '\n'), nil
}

// DecodePublicKey accepts exactly one unpadded URL-safe base64 line, with an
// optional LF or CRLF terminator. Alternate whitespace and padded encodings
// are rejected so provisioning artifacts have one stable representation.
func DecodePublicKey(data []byte) (ed25519.PublicKey, error) {
	if len(data) == 0 || len(data) > 96 {
		return nil, fmt.Errorf("%w: public key encoding size", ErrInvalidSignature)
	}
	text := string(data)
	switch {
	case strings.HasSuffix(text, "\r\n"):
		text = strings.TrimSuffix(text, "\r\n")
	case strings.HasSuffix(text, "\n"):
		text = strings.TrimSuffix(text, "\n")
	}
	if text == "" || strings.ContainsAny(text, " \t\r\n") || strings.Contains(text, "=") {
		return nil, fmt.Errorf("%w: public key encoding whitespace or padding", ErrInvalidSignature)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key encoding", ErrInvalidSignature)
	}
	return ed25519.PublicKey(decoded), nil
}

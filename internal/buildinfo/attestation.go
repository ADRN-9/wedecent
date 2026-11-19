package buildinfo

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"wedecent.com/wedecent/internal/protocol"
)

const identitySigningContext = "wedecent-agent-build-identity-v1\n"

type identityPayload struct {
	DeviceID     string `json:"device_id"`
	Nonce        string `json:"nonce"`
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	SourceSHA256 string `json:"source_sha256"`
	BuiltAt      string `json:"built_at"`
	Go           string `json:"go"`
	Platform     string `json:"platform"`
}

func SignIdentity(deviceID string, privateKey ed25519.PrivateKey, nonce string) (protocol.AgentBuildIdentity, error) {
	if strings.TrimSpace(deviceID) == "" || len(privateKey) != ed25519.PrivateKeySize || !validBuildNonce(nonce) {
		return protocol.AgentBuildIdentity{}, errors.New("invalid agent build identity signing input")
	}
	info := Current()
	payload := identityPayload{
		DeviceID: deviceID, Nonce: nonce, Version: info.Version, Commit: info.Commit,
		SourceSHA256: info.SourceSHA256, BuiltAt: info.BuiltAt, Go: info.Go, Platform: info.Platform,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return protocol.AgentBuildIdentity{}, err
	}
	signature := ed25519.Sign(privateKey, append([]byte(identitySigningContext), encoded...))
	return protocol.AgentBuildIdentity{
		DeviceID: payload.DeviceID, Nonce: payload.Nonce, Version: payload.Version, Commit: payload.Commit,
		SourceSHA256: payload.SourceSHA256, BuiltAt: payload.BuiltAt, Go: payload.Go, Platform: payload.Platform,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func VerifyIdentity(publicKey ed25519.PublicKey, expectedDeviceID, expectedNonce string, attestation protocol.AgentBuildIdentity) error {
	if len(publicKey) != ed25519.PublicKeySize || !validBuildNonce(expectedNonce) ||
		attestation.DeviceID != expectedDeviceID || attestation.Nonce != expectedNonce ||
		attestation.Version == "" || attestation.Commit == "" || attestation.SourceSHA256 == "" ||
		attestation.BuiltAt == "" || attestation.Go == "" || attestation.Platform == "" {
		return errors.New("agent build identity fields are invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(attestation.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("agent build identity signature is malformed")
	}
	payload := identityPayload{
		DeviceID: attestation.DeviceID, Nonce: attestation.Nonce, Version: attestation.Version,
		Commit: attestation.Commit, SourceSHA256: attestation.SourceSHA256, BuiltAt: attestation.BuiltAt,
		Go: attestation.Go, Platform: attestation.Platform,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	message := append([]byte(identitySigningContext), encoded...)
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("agent build identity signature verification failed")
	}
	return nil
}

func validBuildNonce(nonce string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == nonce
}

package updateinfo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	StablePairSchema   = 1
	MaxStablePairBytes = 24 << 10
)

// StablePairEnvelope binds a canonical manifest and its detached signature in
// one immutable JSON object. A single conditional object write can therefore
// move the stable channel without exposing a mixed manifest/signature pair.
type StablePairEnvelope struct {
	Schema    int    `json:"schema"`
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
}

func EncodeCanonicalStablePair(manifestBytes, signatureBytes []byte) ([]byte, error) {
	manifest, err := ParseCanonical(manifestBytes)
	if err != nil {
		return nil, err
	}
	if manifest.Schema != ManifestSchemaV2 {
		return nil, fmt.Errorf("%w: stable pair requires manifest schema v2", ErrInvalidManifest)
	}
	signature, err := DecodeSignature(signatureBytes)
	if err != nil {
		return nil, err
	}
	envelope := StablePairEnvelope{
		Schema:    StablePairSchema,
		Manifest:  base64.RawURLEncoding.EncodeToString(manifestBytes),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: encode stable pair: %v", ErrInvalidManifest, err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxStablePairBytes {
		return nil, fmt.Errorf("%w: stable pair exceeds %d bytes", ErrInvalidManifest, MaxStablePairBytes)
	}
	return encoded, nil
}

func ParseCanonicalStablePair(data []byte) ([]byte, []byte, error) {
	if len(data) == 0 || len(data) > MaxStablePairBytes {
		return nil, nil, fmt.Errorf("%w: stable pair size is invalid", ErrInvalidManifest)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope StablePairEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, nil, fmt.Errorf("%w: decode stable pair: %v", ErrInvalidManifest, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("%w: stable pair has trailing JSON", ErrInvalidManifest)
	}
	if envelope.Schema != StablePairSchema || envelope.Manifest == "" || envelope.Signature == "" {
		return nil, nil, fmt.Errorf("%w: stable pair schema or fields are invalid", ErrInvalidManifest)
	}
	manifestBytes, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: stable pair manifest encoding", ErrInvalidManifest)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != 64 {
		return nil, nil, fmt.Errorf("%w: stable pair signature encoding", ErrInvalidSignature)
	}
	manifest, err := ParseCanonical(manifestBytes)
	if err != nil || manifest.Schema != ManifestSchemaV2 {
		return nil, nil, fmt.Errorf("%w: stable pair requires canonical schema-v2 manifest", ErrInvalidManifest)
	}
	canonical, err := EncodeCanonicalStablePair(manifestBytes, append([]byte(base64.RawURLEncoding.EncodeToString(signature)), '\n'))
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, nil, fmt.Errorf("%w: stable pair is not canonical", ErrInvalidManifest)
	}
	encodedSignature := append([]byte(base64.RawURLEncoding.EncodeToString(signature)), '\n')
	return manifestBytes, encodedSignature, nil
}

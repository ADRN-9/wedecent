package updateinfo

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestCanonicalStablePairRoundTrip(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = publicKey
	manifest := validManifest()
	manifest.Schema = ManifestSchemaV2
	manifest.SigningKeyID = "stable-key-1"
	manifest.KeysetEpoch = 3
	manifestBody, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeSignature(ed25519.Sign(privateKey, manifestBody))
	if err != nil {
		t.Fatal(err)
	}

	pair, err := EncodeCanonicalStablePair(manifestBody, signature)
	if err != nil {
		t.Fatal(err)
	}
	gotManifest, gotSignature, err := ParseCanonicalStablePair(pair)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotManifest, manifestBody) || !bytes.Equal(gotSignature, signature) {
		t.Fatal("stable-pair round trip changed manifest or signature bytes")
	}
}

func TestStablePairRejectsV1AndMalformedEnvelopes(t *testing.T) {
	manifest := validManifest()
	body, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, ed25519.SignatureSize)
	v1Envelope, err := json.Marshal(StablePairEnvelope{
		Schema:    StablePairSchema,
		Manifest:  base64.RawURLEncoding.EncodeToString(body),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	v1Envelope = append(v1Envelope, '\n')
	if _, _, err := ParseCanonicalStablePair(v1Envelope); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("v1 stable pair error = %v, want ErrInvalidManifest", err)
	}

	unknown, err := json.Marshal(map[string]any{
		"schema": StablePairSchema, "manifest": "e30", "signature": "e30", "extra": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	unknown = append(unknown, '\n')
	if _, _, err := ParseCanonicalStablePair(unknown); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("unknown-field pair error = %v, want ErrInvalidManifest", err)
	}
	for _, input := range [][]byte{nil, []byte("{}\n"), append(append([]byte(nil), v1Envelope...), ' ')} {
		if _, _, err := ParseCanonicalStablePair(input); err == nil {
			t.Fatalf("malformed stable pair accepted: %q", input)
		}
	}
}

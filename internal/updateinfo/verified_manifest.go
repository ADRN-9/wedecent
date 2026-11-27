package updateinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// VerifiedManifest is an opaque authorization capability. Its fields are
// intentionally private; only authenticated discovery can construct one.
type VerifiedManifest struct {
	manifest        Manifest
	signerID        string
	keysetEpoch     uint64
	keysetDigest    string
	manifestDigest  string
	previousVersion string
}

var ErrUnverifiedManifest = errors.New("updateinfo: manifest lacks verified update authority")

func (v VerifiedManifest) Manifest() Manifest { return v.manifest }

// VerifyManifestV2Capability is the only capability constructor exposed to
// callers. It delegates to the full v2 signature/keyset verifier first.
func VerifyManifestV2Capability(verified VerifiedKeyset, manifestBytes, signatureBytes []byte, now time.Time, currentVersion string, highestSequence uint64) (VerifiedManifest, error) {
	manifest, err := VerifyManifestV2(verified, manifestBytes, signatureBytes, now, currentVersion, highestSequence)
	if err != nil {
		return VerifiedManifest{}, err
	}
	return verifiedManifestFrom(verified, manifest, manifestBytes, currentVersion)
}

func verifiedManifestFrom(keyset VerifiedKeyset, manifest Manifest, canonicalBytes []byte, previousVersion string) (VerifiedManifest, error) {
	if keyset.digest == "" || keyset.keyset.Epoch == 0 ||
		manifest.Schema != ManifestSchemaV2 ||
		manifest.SigningKeyID == "" || manifest.KeysetEpoch != keyset.keyset.Epoch {
		return VerifiedManifest{}, ErrUnverifiedManifest
	}
	if err := manifest.Validate(); err != nil {
		return VerifiedManifest{}, err
	}
	digest := sha256.Sum256(canonicalBytes)
	return VerifiedManifest{
		manifest: manifest, signerID: manifest.SigningKeyID,
		keysetEpoch: keyset.Epoch(), keysetDigest: keyset.Digest(),
		manifestDigest: hex.EncodeToString(digest[:]), previousVersion: previousVersion,
	}, nil
}

func (v VerifiedManifest) validate() error {
	if v.signerID == "" || v.keysetEpoch == 0 || v.previousVersion == "" ||
		len(v.keysetDigest) != 64 || len(v.manifestDigest) != 64 ||
		v.manifest.Schema != ManifestSchemaV2 ||
		v.manifest.SigningKeyID != v.signerID ||
		v.manifest.KeysetEpoch != v.keysetEpoch {
		return ErrUnverifiedManifest
	}
	if err := v.manifest.Validate(); err != nil {
		return err
	}
	canonical, err := EncodeCanonical(v.manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != v.manifestDigest {
		return fmt.Errorf("%w: manifest capability digest mismatch", ErrUnverifiedManifest)
	}
	if decoded, err := hex.DecodeString(v.keysetDigest); err != nil || len(decoded) != sha256.Size {
		return ErrUnverifiedManifest
	}
	return nil
}

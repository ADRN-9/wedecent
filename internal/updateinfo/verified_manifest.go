package updateinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// VerifiedManifest is an unforgeable admission capability. Its fields are
// private; callers can obtain one only by successful v2 signature verification.
type VerifiedManifest struct {
	manifest       Manifest
	signerID       string
	keysetEpoch    uint64
	keysetDigest   string
	manifestDigest string
	previousVersion string
	highestSequence uint64
}

func (v VerifiedManifest) Manifest() Manifest { return v.manifest }
func (v VerifiedManifest) SignerID() string { return v.signerID }
func (v VerifiedManifest) KeysetEpoch() uint64 { return v.keysetEpoch }
func (v VerifiedManifest) KeysetDigest() string { return v.keysetDigest }
func (v VerifiedManifest) ManifestDigest() string { return v.manifestDigest }

// VerifyManifestV2Capability constructs an admission capability only after
// VerifyManifestV2 has authenticated the exact canonical bytes and policy.
func VerifyManifestV2Capability(
	keyset VerifiedKeyset,
	manifestBytes, signatureBytes []byte,
	now time.Time,
	currentVersion string,
	highestSequence uint64,
) (VerifiedManifest, error) {
	var zero VerifiedManifest
	manifest, err := VerifyManifestV2(keyset, manifestBytes, signatureBytes, now, currentVersion, highestSequence)
	if err != nil {
		return zero, err
	}
	digest := sha256.Sum256(manifestBytes)
	capability := VerifiedManifest{
		manifest: manifest,
		signerID: manifest.SigningKeyID,
		keysetEpoch: keyset.Epoch(),
		keysetDigest: keyset.Digest(),
		manifestDigest: hex.EncodeToString(digest[:]),
		previousVersion: currentVersion,
		highestSequence: highestSequence,
	}
	if err := capability.validate(); err != nil {
		return zero, err
	}
	return capability, nil
}

func (v VerifiedManifest) validate() error {
	if v.signerID == "" || v.keysetEpoch == 0 || v.keysetDigest == "" ||
		v.manifestDigest == "" || v.previousVersion == "" {
		return fmt.Errorf("%w: incomplete verified manifest capability", ErrInvalidManifest)
	}
	if err := v.manifest.Validate(); err != nil { return err }
	if v.manifest.Schema != ManifestSchemaV2 ||
		v.manifest.SigningKeyID != v.signerID ||
		v.manifest.KeysetEpoch != v.keysetEpoch ||
		v.manifest.Sequence <= v.highestSequence {
		return fmt.Errorf("%w: capability metadata mismatch", ErrInvalidManifest)
	}
	canonical, err := EncodeCanonical(v.manifest)
	if err != nil { return err }
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != v.manifestDigest {
		return fmt.Errorf("%w: capability manifest digest mismatch", ErrInvalidManifest)
	}
	return nil
}

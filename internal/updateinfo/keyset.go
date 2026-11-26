package updateinfo

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	KeysetSchemaV1       = 1
	ManifestSchemaV2     = 2
	MaxKeysetBytes       = 32 << 10
	MaxKeysetEntries     = 64
	MaxKeysetValidity    = 90 * 24 * time.Hour
	MaxKeysetClockSkew   = 5 * time.Minute
)

var (
	ErrInvalidKeyset       = errors.New("updateinfo: invalid update keyset")
	ErrKeysetRollback      = errors.New("updateinfo: keyset rollback or equivocation rejected")
	ErrUnknownSigningKey   = errors.New("updateinfo: manifest signing key is not authorized")
	ErrRevokedSigningKey   = errors.New("updateinfo: manifest signing key is revoked")
	keyIDPattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

type KeysetEntry struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Status    string `json:"status"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

type Keyset struct {
	Schema    int           `json:"schema"`
	Epoch     uint64        `json:"epoch"`
	RootKeyID string        `json:"root_key_id"`
	IssuedAt  string        `json:"issued_at"`
	ExpiresAt string        `json:"expires_at"`
	Keys      []KeysetEntry `json:"keys"`
}

// VerifiedKeyset is returned only after root-signature, canonical encoding,
// validity-window and anti-rollback checks have succeeded.
type VerifiedKeyset struct {
	keyset Keyset
	digest string
}

func (v VerifiedKeyset) Epoch() uint64 { return v.keyset.Epoch }
func (v VerifiedKeyset) Digest() string { return v.digest }

func (k Keyset) Validate(now time.Time) error {
	if k.Schema != KeysetSchemaV1 || k.Epoch == 0 || !keyIDPattern.MatchString(k.RootKeyID) {
		return fmt.Errorf("%w: schema, epoch or root key ID", ErrInvalidKeyset)
	}
	if len(k.Keys) == 0 || len(k.Keys) > MaxKeysetEntries {
		return fmt.Errorf("%w: key count is invalid", ErrInvalidKeyset)
	}
	issuedAt, err := parseKeysetTime(k.IssuedAt)
	if err != nil {
		return fmt.Errorf("%w: issued_at: %v", ErrInvalidKeyset, err)
	}
	expiresAt, err := parseKeysetTime(k.ExpiresAt)
	if err != nil {
		return fmt.Errorf("%w: expires_at: %v", ErrInvalidKeyset, err)
	}
	if issuedAt.After(now.Add(MaxKeysetClockSkew)) || !expiresAt.After(now) ||
		!expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxKeysetValidity {
		return fmt.Errorf("%w: keyset validity window", ErrInvalidKeyset)
	}

	seenKeys := make(map[string]struct{}, len(k.Keys))
	seenPublic := make(map[string]struct{}, len(k.Keys))
	lastID := ""
	for _, entry := range k.Keys {
		if !keyIDPattern.MatchString(entry.ID) || (lastID != "" && entry.ID <= lastID) {
			return fmt.Errorf("%w: key IDs must be unique and sorted", ErrInvalidKeyset)
		}
		lastID = entry.ID
		if _, exists := seenKeys[entry.ID]; exists {
			return fmt.Errorf("%w: duplicate key ID", ErrInvalidKeyset)
		}
		seenKeys[entry.ID] = struct{}{}

		if strings.ContainsAny(entry.PublicKey, " \t\r\n") {
			return fmt.Errorf("%w: key %q public key whitespace", ErrInvalidKeyset, entry.ID)
		}
		publicKey, err := DecodePublicKey([]byte(entry.PublicKey))
		if err != nil {
			return fmt.Errorf("%w: key %q public key: %v", ErrInvalidKeyset, entry.ID, err)
		}
		publicFingerprint := hex.EncodeToString(publicKey)
		if _, exists := seenPublic[publicFingerprint]; exists {
			return fmt.Errorf("%w: duplicate public key material", ErrInvalidKeyset)
		}
		seenPublic[publicFingerprint] = struct{}{}

		notBefore, err := parseKeysetTime(entry.NotBefore)
		if err != nil {
			return fmt.Errorf("%w: key %q not_before: %v", ErrInvalidKeyset, entry.ID, err)
		}
		notAfter, err := parseKeysetTime(entry.NotAfter)
		if err != nil || !notAfter.After(notBefore) {
			return fmt.Errorf("%w: key %q validity interval", ErrInvalidKeyset, entry.ID)
		}
		switch entry.Status {
		case "active", "verify-only":
			if entry.RevokedAt != "" || now.Before(notBefore) || !now.Before(notAfter) {
				return fmt.Errorf("%w: key %q is outside its authorization window", ErrInvalidKeyset, entry.ID)
			}
		case "revoked":
			if entry.RevokedAt == "" {
				return fmt.Errorf("%w: revoked key %q has no revocation time", ErrInvalidKeyset, entry.ID)
			}
			revokedAt, err := parseKeysetTime(entry.RevokedAt)
			if err != nil || revokedAt.Before(notBefore) {
				return fmt.Errorf("%w: key %q revocation time", ErrInvalidKeyset, entry.ID)
			}
		default:
			return fmt.Errorf("%w: key %q has unknown status", ErrInvalidKeyset, entry.ID)
		}
	}
	return nil
}

func EncodeCanonicalKeyset(keyset Keyset, now time.Time) ([]byte, error) {
	if err := keyset.Validate(now); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(keyset)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidKeyset, err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxKeysetBytes {
		return nil, fmt.Errorf("%w: keyset exceeds %d bytes", ErrInvalidKeyset, MaxKeysetBytes)
	}
	return encoded, nil
}

func ParseCanonicalKeyset(data []byte, now time.Time) (Keyset, error) {
	var zero Keyset
	if len(data) == 0 || len(data) > MaxKeysetBytes {
		return zero, fmt.Errorf("%w: keyset size", ErrInvalidKeyset)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var keyset Keyset
	if err := decoder.Decode(&keyset); err != nil {
		return zero, fmt.Errorf("%w: decode: %v", ErrInvalidKeyset, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return zero, fmt.Errorf("%w: multiple JSON values", ErrInvalidKeyset)
		}
		return zero, fmt.Errorf("%w: trailing data: %v", ErrInvalidKeyset, err)
	}
	canonical, err := EncodeCanonicalKeyset(keyset, now)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(data, canonical) {
		return zero, fmt.Errorf("%w: keyset is not canonical", ErrInvalidKeyset)
	}
	return keyset, nil
}

// VerifyKeyset authenticates a root-signed keyset and rejects stale epochs or
// same-epoch equivocation. The caller persists the returned epoch and digest
// in its integrity-protected update state.
func VerifyKeyset(rootKeyID string, rootPublicKey ed25519.PublicKey, keysetBytes, signatureBytes []byte, now time.Time, highestEpoch uint64, highestDigest string) (VerifiedKeyset, error) {
	var zero VerifiedKeyset
	if !keyIDPattern.MatchString(rootKeyID) || len(rootPublicKey) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("%w: pinned root identity", ErrInvalidKeyset)
	}
	if len(keysetBytes) == 0 || len(keysetBytes) > MaxKeysetBytes {
		return zero, fmt.Errorf("%w: keyset size", ErrInvalidKeyset)
	}
	signature, err := DecodeSignature(signatureBytes)
	if err != nil || !ed25519.Verify(rootPublicKey, keysetBytes, signature) {
		return zero, fmt.Errorf("%w: root signature", ErrInvalidKeyset)
	}
	keyset, err := ParseCanonicalKeyset(keysetBytes, now)
	if err != nil {
		return zero, err
	}
	if keyset.RootKeyID != rootKeyID {
		return zero, fmt.Errorf("%w: keyset root key ID mismatch", ErrInvalidKeyset)
	}
	digestBytes := sha256.Sum256(keysetBytes)
	digest := hex.EncodeToString(digestBytes[:])
	if highestEpoch == 0 {
		if highestDigest != "" {
			return zero, ErrKeysetRollback
		}
	} else if len(highestDigest) != 64 {
		return zero, ErrKeysetRollback
	} else if _, err := hex.DecodeString(highestDigest); err != nil {
		return zero, ErrKeysetRollback
	}
	if keyset.Epoch < highestEpoch ||
		(keyset.Epoch == highestEpoch && digest != highestDigest) {
		return zero, ErrKeysetRollback
	}
	return VerifiedKeyset{keyset: keyset, digest: digest}, nil
}

// VerifyManifestV2 requires a manifest key authorized by the verified keyset.
// New stable discovery accepts only active keys; verify-only and revoked keys
// cannot authorize a newly discovered stable manifest.
func VerifyManifestV2(verified VerifiedKeyset, manifestBytes, signatureBytes []byte, now time.Time, currentVersion string, highestSequence uint64) (Manifest, error) {
	var zero Manifest
	if verified.digest == "" || verified.keyset.Epoch == 0 {
		return zero, fmt.Errorf("%w: unverified keyset", ErrInvalidKeyset)
	}
	if err := verified.keyset.Validate(now); err != nil {
		return zero, err
	}
	manifest, err := ParseCanonical(manifestBytes)
	if err != nil {
		return zero, err
	}
	if manifest.Schema != ManifestSchemaV2 || manifest.KeysetEpoch != verified.keyset.Epoch {
		return zero, fmt.Errorf("%w: manifest schema or keyset epoch mismatch", ErrInvalidManifest)
	}
	var selected *KeysetEntry
	for i := range verified.keyset.Keys {
		if verified.keyset.Keys[i].ID == manifest.SigningKeyID {
			selected = &verified.keyset.Keys[i]
			break
		}
	}
	if selected == nil {
		return zero, ErrUnknownSigningKey
	}
	if selected.Status == "revoked" {
		return zero, ErrRevokedSigningKey
	}
	if selected.Status != "active" {
		return zero, ErrUnknownSigningKey
	}
	notBefore, _ := parseKeysetTime(selected.NotBefore)
	notAfter, _ := parseKeysetTime(selected.NotAfter)
	if now.Before(notBefore) || !now.Before(notAfter) {
		return zero, ErrUnknownSigningKey
	}
	publishedAt, err := parseKeysetTime(manifest.PublishedAt)
	if err != nil || publishedAt.Before(notBefore) || !publishedAt.Before(notAfter) || publishedAt.After(now.Add(MaxKeysetClockSkew)) {
		return zero, fmt.Errorf("%w: manifest publication time is outside signing-key validity", ErrInvalidManifest)
	}
	publicKey, err := DecodePublicKey([]byte(selected.PublicKey))
	if err != nil {
		return zero, fmt.Errorf("%w: authorized key encoding", ErrInvalidKeyset)
	}
	signature, err := DecodeSignature(signatureBytes)
	if err != nil || !ed25519.Verify(publicKey, manifestBytes, signature) {
		return zero, ErrInvalidSignature
	}
	if currentVersion != "" {
		if err := CheckAdvance(currentVersion, highestSequence, manifest); err != nil {
			return zero, err
		}
	} else if highestSequence != 0 {
		return zero, fmt.Errorf("%w: current version is required with a persisted sequence", ErrRollback)
	}
	return manifest, nil
}

func parseKeysetTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("must be canonical UTC RFC3339 seconds")
	}
	return parsed, nil
}

// SortKeysetEntries sorts entries before canonical encoding; parsing still
// rejects unsorted input so there is only one signed representation.
func SortKeysetEntries(entries []KeysetEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
}

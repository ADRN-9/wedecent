package updateinfo

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
	"time"
)

const (
	ManifestSchemaV1 = 1
	StableChannel    = "stable"
	DownloadHost     = "downloads.wedecent.com"
	MaxManifestBytes = 16 << 10
)

var (
	ErrInvalidManifest  = errors.New("updateinfo: invalid manifest")
	ErrInvalidSignature = errors.New("updateinfo: invalid manifest signature")
	ErrRollback         = errors.New("updateinfo: update rollback rejected")

	stableVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
)

// Manifest is the canonical, signed update-discovery record for the stable
// Windows channel. It intentionally points only at immutable versioned public
// artifacts. The mutable channel object is a discovery hint; artifact
// authenticity still remains independently protected by Authenticode.
type Manifest struct {
	Schema          int    `json:"schema"`
	Channel         string `json:"channel"`
	Sequence        uint64 `json:"sequence"`
	Version         string `json:"version"`
	PublishedAt     string `json:"published_at"`
	ReleaseURL      string `json:"release_url"`
	ReleaseSHA256   string `json:"release_sha256"`
	InstallerURL    string `json:"installer_url"`
	InstallerSHA256 string `json:"installer_sha256"`
}

func (m Manifest) Validate() error {
	if m.Schema != ManifestSchemaV1 {
		return fmt.Errorf("%w: schema must be %d", ErrInvalidManifest, ManifestSchemaV1)
	}
	if m.Channel != StableChannel {
		return fmt.Errorf("%w: unsupported channel %q", ErrInvalidManifest, m.Channel)
	}
	if m.Sequence == 0 {
		return fmt.Errorf("%w: sequence must be positive", ErrInvalidManifest)
	}
	if _, err := parseStableVersion(m.Version); err != nil {
		return err
	}
	if err := validatePublishedAt(m.PublishedAt); err != nil {
		return err
	}
	if err := validateSHA256(m.ReleaseSHA256, "release_sha256"); err != nil {
		return err
	}
	if err := validateSHA256(m.InstallerSHA256, "installer_sha256"); err != nil {
		return err
	}

	releasePath := fmt.Sprintf(
		"/windows/%s/wedecent-%s-windows-amd64.zip",
		m.Version,
		m.Version,
	)
	if err := validateDownloadURL(m.ReleaseURL, releasePath, "release_url"); err != nil {
		return err
	}
	installerPath := fmt.Sprintf(
		"/windows/%s/wedecent-%s-windows-installer.zip",
		m.Version,
		m.Version,
	)
	if err := validateDownloadURL(m.InstallerURL, installerPath, "installer_url"); err != nil {
		return err
	}
	return nil
}

// EncodeCanonical returns the only byte representation that may be signed.
// A trailing LF is part of the canonical representation so files remain
// friendly to standard text tooling without introducing encoding ambiguity.
func EncodeCanonical(m Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidManifest, err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: manifest exceeds %d bytes", ErrInvalidManifest, MaxManifestBytes)
	}
	return encoded, nil
}

// ParseCanonical rejects unknown fields, extra JSON values, alternate
// whitespace/field order, duplicate-field encodings, and oversized inputs.
func ParseCanonical(data []byte) (Manifest, error) {
	var zero Manifest
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return zero, fmt.Errorf("%w: manifest size is invalid", ErrInvalidManifest)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return zero, fmt.Errorf("%w: decode: %v", ErrInvalidManifest, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return zero, fmt.Errorf("%w: multiple JSON values", ErrInvalidManifest)
		}
		return zero, fmt.Errorf("%w: trailing data: %v", ErrInvalidManifest, err)
	}

	canonical, err := EncodeCanonical(manifest)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(data, canonical) {
		return zero, fmt.Errorf("%w: manifest is not canonical", ErrInvalidManifest)
	}
	return manifest, nil
}

// Verify authenticates the exact canonical manifest bytes with a pinned
// Ed25519 public key before returning parsed fields. The caller owns public-key
// provisioning; no production update key is embedded by this package.
func Verify(publicKey ed25519.PublicKey, manifestBytes, signatureBytes []byte) (Manifest, error) {
	var zero Manifest
	if len(publicKey) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("%w: public key length", ErrInvalidSignature)
	}
	if len(manifestBytes) == 0 || len(manifestBytes) > MaxManifestBytes {
		return zero, fmt.Errorf("%w: manifest size", ErrInvalidManifest)
	}
	signature, err := DecodeSignature(signatureBytes)
	if err != nil {
		return zero, err
	}
	if !ed25519.Verify(publicKey, manifestBytes, signature) {
		return zero, ErrInvalidSignature
	}
	return ParseCanonical(manifestBytes)
}

func EncodeSignature(signature []byte) ([]byte, error) {
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature length", ErrInvalidSignature)
	}
	encoded := base64.RawURLEncoding.EncodeToString(signature)
	return append([]byte(encoded), '\n'), nil
}

func DecodeSignature(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 128 {
		return nil, fmt.Errorf("%w: signature encoding size", ErrInvalidSignature)
	}
	text := string(data)
	switch {
	case strings.HasSuffix(text, "\r\n"):
		text = strings.TrimSuffix(text, "\r\n")
	case strings.HasSuffix(text, "\n"):
		text = strings.TrimSuffix(text, "\n")
	}
	if text == "" || strings.ContainsAny(text, " \t\r\n") {
		return nil, fmt.Errorf("%w: signature encoding whitespace", ErrInvalidSignature)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature encoding", ErrInvalidSignature)
	}
	return signature, nil
}

// CompareStableVersions compares strict vMAJOR.MINOR.PATCH versions and
// returns -1, 0, or 1. Components are arbitrary precision so malformed large
// version numbers cannot overflow an integer during update checks.
func CompareStableVersions(left, right string) (int, error) {
	l, err := parseStableVersion(left)
	if err != nil {
		return 0, err
	}
	r, err := parseStableVersion(right)
	if err != nil {
		return 0, err
	}
	for i := range l {
		if cmp := l[i].Cmp(r[i]); cmp < 0 {
			return -1, nil
		} else if cmp > 0 {
			return 1, nil
		}
	}
	return 0, nil
}

// CheckAdvance rejects a signed record that does not advance both the
// persisted manifest sequence and the installed stable version. Persisting the
// highest accepted sequence is the caller's responsibility.
func CheckAdvance(currentVersion string, currentSequence uint64, candidate Manifest) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	if candidate.Sequence <= currentSequence {
		return fmt.Errorf("%w: sequence %d is not newer than %d", ErrRollback, candidate.Sequence, currentSequence)
	}
	cmp, err := CompareStableVersions(candidate.Version, currentVersion)
	if err != nil {
		return err
	}
	if cmp <= 0 {
		return fmt.Errorf("%w: version %s is not newer than %s", ErrRollback, candidate.Version, currentVersion)
	}
	return nil
}

func parseStableVersion(version string) ([3]*big.Int, error) {
	var result [3]*big.Int
	match := stableVersionPattern.FindStringSubmatch(version)
	if match == nil {
		return result, fmt.Errorf("%w: version must be canonical vMAJOR.MINOR.PATCH", ErrInvalidManifest)
	}
	for i := range result {
		value, ok := new(big.Int).SetString(match[i+1], 10)
		if !ok {
			return result, fmt.Errorf("%w: invalid version component", ErrInvalidManifest)
		}
		result[i] = value
	}
	return result, nil
}

func validatePublishedAt(value string) error {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return fmt.Errorf("%w: published_at must be canonical UTC RFC3339 seconds", ErrInvalidManifest)
	}
	return nil
}

func validateSHA256(value, field string) error {
	if len(value) != 64 || strings.ToLower(value) != value {
		return fmt.Errorf("%w: %s must be lowercase SHA-256 hex", ErrInvalidManifest, field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%w: %s must be lowercase SHA-256 hex", ErrInvalidManifest, field)
	}
	return nil
}

func validateDownloadURL(raw, expectedPath, field string) error {
	expected := "https://" + DownloadHost + expectedPath
	if raw != expected {
		return fmt.Errorf("%w: %s is not the canonical immutable download URL", ErrInvalidManifest, field)
	}
	return nil
}

package updateinfo

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func validManifest() Manifest {
	return Manifest{
		Schema:          ManifestSchemaV1,
		Channel:         StableChannel,
		Sequence:        42,
		Version:         "v1.2.3",
		PublishedAt:     "2026-09-23T20:00:00Z",
		ReleaseURL:      "https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-amd64.zip",
		ReleaseSHA256:   strings.Repeat("a", 64),
		InstallerURL:    "https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-installer.zip",
		InstallerSHA256: strings.Repeat("b", 64),
	}
}

func TestCanonicalManifestRoundTrip(t *testing.T) {
	manifest := validManifest()
	encoded, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' {
		t.Fatal("canonical manifest is missing its trailing LF")
	}
	if strings.Contains(string(encoded), "\n ") || strings.Contains(string(encoded), "\t") {
		t.Fatalf("canonical manifest unexpectedly contains indentation: %q", encoded)
	}

	parsed, err := ParseCanonical(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != manifest {
		t.Fatalf("parsed manifest = %#v, want %#v", parsed, manifest)
	}
}

func TestParseCanonicalRejectsAlternateEncodings(t *testing.T) {
	canonical, err := EncodeCanonical(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	plain := strings.TrimSuffix(string(canonical), "\n")

	tests := map[string][]byte{
		"leading whitespace":  append([]byte(" "), canonical...),
		"missing trailing LF": []byte(plain),
		"extra trailing LF":   append(append([]byte(nil), canonical...), '\n'),
		"pretty JSON": []byte(`{
  "schema": 1,
  "channel": "stable",
  "sequence": 42,
  "version": "v1.2.3",
  "published_at": "2026-09-23T20:00:00Z",
  "release_url": "https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-amd64.zip",
  "release_sha256": "` + strings.Repeat("a", 64) + `",
  "installer_url": "https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-installer.zip",
  "installer_sha256": "` + strings.Repeat("b", 64) + `"
}
`),
		"reordered fields": []byte(`{"channel":"stable","schema":1,"sequence":42,"version":"v1.2.3","published_at":"2026-09-23T20:00:00Z","release_url":"https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-amd64.zip","release_sha256":"` + strings.Repeat("a", 64) + `","installer_url":"https://downloads.wedecent.com/windows/v1.2.3/wedecent-v1.2.3-windows-installer.zip","installer_sha256":"` + strings.Repeat("b", 64) + `"}
`),
		"unknown field":   []byte(strings.Replace(plain, `"schema":1`, `"schema":1,"extra":true`, 1) + "\n"),
		"duplicate field": []byte(strings.Replace(plain, `"schema":1`, `"schema":1,"schema":1`, 1) + "\n"),
		"multiple values": append(append([]byte(nil), canonical...), []byte("{}\n")...),
		"trailing junk":   append(append([]byte(nil), canonical...), []byte("junk")...),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCanonical(input); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("ParseCanonical() error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestParseCanonicalRejectsOversizedInput(t *testing.T) {
	input := bytesOf('x', MaxManifestBytes+1)
	if _, err := ParseCanonical(input); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("ParseCanonical() error = %v, want ErrInvalidManifest", err)
	}
}

func TestVerifySignedManifest(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest()
	body, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	rawSignature := ed25519.Sign(privateKey, body)
	encodedSignature, err := EncodeSignature(rawSignature)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Verify(publicKey, body, encodedSignature)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != manifest {
		t.Fatalf("Verify() manifest = %#v, want %#v", parsed, manifest)
	}

	crlf := append([]byte(strings.TrimSuffix(string(encodedSignature), "\n")), '\r', '\n')
	if _, err := Verify(publicKey, body, crlf); err != nil {
		t.Fatalf("Verify() rejected canonical CRLF signature file: %v", err)
	}
}

func TestVerifyRejectsTamperingAndWrongKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeCanonical(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeSignature(ed25519.Sign(privateKey, body))
	if err != nil {
		t.Fatal(err)
	}

	mutated := append([]byte(nil), body...)
	mutated[len(mutated)-2] ^= 1
	if _, err := Verify(publicKey, mutated, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered Verify() error = %v, want ErrInvalidSignature", err)
	}
	if _, err := Verify(otherPublicKey, body, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong-key Verify() error = %v, want ErrInvalidSignature", err)
	}
	if _, err := Verify(publicKey[:ed25519.PublicKeySize-1], body, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("short-key Verify() error = %v, want ErrInvalidSignature", err)
	}
}

func TestSignatureEncodingRejectsMalformedInput(t *testing.T) {
	valid := make([]byte, ed25519.SignatureSize)
	encoded, err := EncodeSignature(valid)
	if err != nil {
		t.Fatal(err)
	}

	tests := [][]byte{
		nil,
		[]byte("not-base64!\n"),
		[]byte(" Zm9v\n"),
		[]byte("Zm9v \n"),
		[]byte("Zm9v\n\n"),
		[]byte(strings.TrimSuffix(string(encoded), "\n") + "="),
		[]byte(strings.Repeat("A", 127)),
	}
	for _, input := range tests {
		if _, err := DecodeSignature(input); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("DecodeSignature(%q) error = %v, want ErrInvalidSignature", input, err)
		}
	}

	if _, err := EncodeSignature(valid[:len(valid)-1]); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("EncodeSignature(short) error = %v, want ErrInvalidSignature", err)
	}
}

func TestManifestValidationRejectsInvalidFields(t *testing.T) {
	tests := map[string]func(*Manifest){
		"schema":             func(m *Manifest) { m.Schema = 2 },
		"channel":            func(m *Manifest) { m.Channel = "beta" },
		"zero sequence":      func(m *Manifest) { m.Sequence = 0 },
		"prerelease":         func(m *Manifest) { m.Version = "v1.2.3-rc.1" },
		"leading zero":       func(m *Manifest) { m.Version = "v01.2.3" },
		"fractional time":    func(m *Manifest) { m.PublishedAt = "2026-09-23T20:00:00.1Z" },
		"non-UTC time":       func(m *Manifest) { m.PublishedAt = "2026-09-23T16:00:00-04:00" },
		"uppercase hash":     func(m *Manifest) { m.ReleaseSHA256 = strings.Repeat("A", 64) },
		"short hash":         func(m *Manifest) { m.InstallerSHA256 = strings.Repeat("b", 63) },
		"wrong scheme":       func(m *Manifest) { m.ReleaseURL = strings.Replace(m.ReleaseURL, "https://", "http://", 1) },
		"wrong host":         func(m *Manifest) { m.ReleaseURL = strings.Replace(m.ReleaseURL, DownloadHost, "example.com", 1) },
		"host port":          func(m *Manifest) { m.ReleaseURL = strings.Replace(m.ReleaseURL, DownloadHost, DownloadHost+":443", 1) },
		"query":              func(m *Manifest) { m.InstallerURL += "?download=1" },
		"fragment":           func(m *Manifest) { m.InstallerURL += "#fragment" },
		"wrong release path": func(m *Manifest) { m.ReleaseURL = strings.Replace(m.ReleaseURL, "windows-amd64.zip", "other.zip", 1) },
		"encoded path":       func(m *Manifest) { m.ReleaseURL = strings.Replace(m.ReleaseURL, "/windows/", "/%77indows/", 1) },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := validManifest()
			mutate(&manifest)
			if err := manifest.Validate(); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestCompareStableVersions(t *testing.T) {
	tests := []struct {
		left  string
		right string
		want  int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"v1.2.4", "v1.2.3", 1},
		{"v1.3.0", "v1.2.99", 1},
		{"v2.0.0", "v1.999.999", 1},
		{"v0.9.9", "v1.0.0", -1},
		{"v999999999999999999999999999999.0.0", "v999999999999999999999999999998.999.999", 1},
	}
	for _, test := range tests {
		got, err := CompareStableVersions(test.left, test.right)
		if err != nil {
			t.Fatalf("CompareStableVersions(%q, %q): %v", test.left, test.right, err)
		}
		if got != test.want {
			t.Fatalf("CompareStableVersions(%q, %q) = %d, want %d", test.left, test.right, got, test.want)
		}
	}

	for _, invalid := range []string{"1.2.3", "v1.2", "v1.2.3-rc.1", "v01.2.3"} {
		if _, err := CompareStableVersions(invalid, "v1.2.3"); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("CompareStableVersions(%q, valid) error = %v, want ErrInvalidManifest", invalid, err)
		}
	}
}

func TestCheckAdvance(t *testing.T) {
	candidate := validManifest()
	if err := CheckAdvance("v1.2.2", 41, candidate); err != nil {
		t.Fatalf("CheckAdvance(newer) = %v", err)
	}

	tests := map[string]func(*Manifest, *string, *uint64){
		"equal sequence": func(m *Manifest, currentVersion *string, currentSequence *uint64) { *currentSequence = m.Sequence },
		"older sequence": func(m *Manifest, currentVersion *string, currentSequence *uint64) { *currentSequence = m.Sequence + 1 },
		"equal version":  func(m *Manifest, currentVersion *string, currentSequence *uint64) { *currentVersion = m.Version },
		"older version":  func(m *Manifest, currentVersion *string, currentSequence *uint64) { *currentVersion = "v2.0.0" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := validManifest()
			currentVersion := "v1.2.2"
			currentSequence := uint64(41)
			mutate(&manifest, &currentVersion, &currentSequence)
			if err := CheckAdvance(currentVersion, currentSequence, manifest); !errors.Is(err, ErrRollback) {
				t.Fatalf("CheckAdvance() error = %v, want ErrRollback", err)
			}
		})
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}

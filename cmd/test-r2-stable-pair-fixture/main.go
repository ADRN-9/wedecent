package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/updateinfo"
)

func main() {
	if len(os.Args) != 3 {
		fail("usage: test-r2-stable-pair-fixture <output-dir> <version>")
	}
	dir, version := os.Args[1], os.Args[2]
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fail("mkdir: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fail("root key: %v", err)
	}
	manifestPublic, manifestPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fail("manifest key: %v", err)
	}
	rootID, signingID := "test-root-1", "stable-test-1"
	encodedManifestPublic, err := updateinfo.EncodePublicKey(manifestPublic)
	if err != nil {
		fail("encode manifest public key: %v", err)
	}
	keyset := updateinfo.Keyset{
		Schema:    updateinfo.KeysetSchemaV1,
		Epoch:     1,
		RootKeyID: rootID,
		IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		Keys: []updateinfo.KeysetEntry{{
			ID:        signingID,
			PublicKey: strings.TrimSpace(string(encodedManifestPublic)),
			NotBefore: now.Add(-time.Minute).Format(time.RFC3339),
			NotAfter:  now.Add(12 * time.Hour).Format(time.RFC3339),
			Status:    "active",
		}},
	}
	keysetBody, err := updateinfo.EncodeCanonicalKeyset(keyset, now)
	if err != nil {
		fail("encode keyset: %v", err)
	}
	keysetSignature, err := updateinfo.EncodeSignature(ed25519.Sign(rootPrivate, keysetBody))
	if err != nil {
		fail("sign keyset: %v", err)
	}
	rootPublicBytes, err := updateinfo.EncodePublicKey(rootPublic)
	if err != nil {
		fail("encode root public key: %v", err)
	}
	write(filepath.Join(dir, "root.pub"), rootPublicBytes)
	write(filepath.Join(dir, "keyset.json"), keysetBody)
	write(filepath.Join(dir, "keyset.sig"), keysetSignature)
	verified, err := updateinfo.VerifyKeyset(rootID, rootPublic, keysetBody, keysetSignature, now, 0, "")
	if err != nil {
		fail("verify fixture keyset: %v", err)
	}

	var firstPair []byte
	for _, sequence := range []uint64{42, 43, 44} {
		manifest := updateinfo.Manifest{
			Schema:          updateinfo.ManifestSchemaV2,
			SigningKeyID:    signingID,
			KeysetEpoch:     keyset.Epoch,
			Channel:         updateinfo.StableChannel,
			Sequence:        sequence,
			Version:         version,
			PublishedAt:     now.Format(time.RFC3339),
			ReleaseURL:      fmt.Sprintf("https://%s/windows/%s/wedecent-%s-windows-amd64.zip", updateinfo.DownloadHost, version, version),
			ReleaseSHA256:   strings.Repeat("a", 64),
			InstallerURL:    fmt.Sprintf("https://%s/windows/%s/wedecent-%s-windows-installer.zip", updateinfo.DownloadHost, version, version),
			InstallerSHA256: strings.Repeat("b", 64),
		}
		manifestBody, err := updateinfo.EncodeCanonical(manifest)
		if err != nil {
			fail("encode manifest: %v", err)
		}
		manifestSignature, err := updateinfo.EncodeSignature(ed25519.Sign(manifestPrivate, manifestBody))
		if err != nil {
			fail("sign manifest: %v", err)
		}
		pair, err := updateinfo.EncodeCanonicalStablePair(manifestBody, manifestSignature)
		if err != nil {
			fail("encode pair: %v", err)
		}
		prefix := fmt.Sprintf("candidate-%d", sequence)
		write(filepath.Join(dir, prefix+".json"), manifestBody)
		write(filepath.Join(dir, prefix+".sig"), manifestSignature)
		write(filepath.Join(dir, prefix+".pair"), pair)
		expected := "-"
		if sequence > 42 {
			sum := sha256.Sum256(firstPair)
			expected = fmt.Sprintf("%x", sum)
		}
		firstPair = pair
		pairSum := sha256.Sum256(pair)
		keysetSum := sha256.Sum256(keysetBody)
		keysetSignatureSum := sha256.Sum256(keysetSignature)
		rootSum := sha256.Sum256(rootPublicBytes)
		receipt := fmt.Sprintf(
			"candidate_pair_sha256=%x\nexpected_pair_sha256=%s\nkeyset_sha256=%x\nkeyset_signature_sha256=%x\nroot_public_key_sha256=%x\nsequence=%d\nversion=%s\nkeyset_epoch=%d\nkeyset_digest=%s\n",
			pairSum, expected, keysetSum, keysetSignatureSum, rootSum, sequence, version, verified.Epoch(), verified.Digest(),
		)
		write(filepath.Join(dir, prefix+".receipt"), []byte(receipt))
	}
}

func write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fail("write %s: %v", path, err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

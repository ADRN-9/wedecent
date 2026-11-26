package updateinfo

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func keysetFixture(t *testing.T, now time.Time) (ed25519.PublicKey, ed25519.PrivateKey, Keyset) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := EncodePublicKey(manifestPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyset := Keyset{
		Schema: KeysetSchemaV1, Epoch: 7, RootKeyID: "wedecent-update-root-1",
		IssuedAt: now.Add(-time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt: now.Add(24*time.Hour).UTC().Format(time.RFC3339),
		Keys: []KeysetEntry{{
			ID: "stable-2026-01", PublicKey: string(bytesTrimLine(encodedPublic)),
			NotBefore: now.Add(-time.Hour).UTC().Format(time.RFC3339),
			NotAfter: now.Add(12*time.Hour).UTC().Format(time.RFC3339), Status: "active",
		}},
	}
	return rootPublic, rootPrivate, keyset
}

func bytesTrimLine(value []byte) []byte {
	if len(value) > 0 && value[len(value)-1] == '\n' {
		return value[:len(value)-1]
	}
	return value
}

func signKeyset(t *testing.T, keyset Keyset, rootPrivate ed25519.PrivateKey, now time.Time) ([]byte, []byte) {
	t.Helper()
	body, err := EncodeCanonicalKeyset(keyset, now)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeSignature(ed25519.Sign(rootPrivate, body))
	if err != nil {
		t.Fatal(err)
	}
	return body, signature
}

func TestKeysetCanonicalVerificationAndEpochPersistence(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, keyset := keysetFixture(t, now)
	body, signature := signKeyset(t, keyset, rootPrivate, now)

	verified, err := VerifyKeyset(keyset.RootKeyID, rootPublic, body, signature, now, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if verified.Epoch() != keyset.Epoch || verified.Digest() == "" {
		t.Fatalf("verified keyset metadata = epoch %d digest %q", verified.Epoch(), verified.Digest())
	}

	same, err := VerifyKeyset(keyset.RootKeyID, rootPublic, body, signature, now, keyset.Epoch, verified.Digest())
	if err != nil {
		t.Fatalf("identical persisted keyset was rejected: %v", err)
	}
	if same.Digest() != verified.Digest() {
		t.Fatal("identical keyset digest changed")
	}
	if _, err := VerifyKeyset(keyset.RootKeyID, rootPublic, body, signature, now, keyset.Epoch+1, verified.Digest()); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("lower epoch error = %v, want ErrKeysetRollback", err)
	}
	if _, err := VerifyKeyset(keyset.RootKeyID, rootPublic, body, signature, now, keyset.Epoch, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("same-epoch equivocation error = %v, want ErrKeysetRollback", err)
	}
	if _, err := VerifyKeyset("different-root", rootPublic, body, signature, now, 0, ""); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("wrong root ID error = %v, want ErrInvalidKeyset", err)
	}
}

func TestKeysetRejectsTamperingExpiryAndNonCanonicalEncoding(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, keyset := keysetFixture(t, now)
	body, signature := signKeyset(t, keyset, rootPrivate, now)

	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifyKeyset(keyset.RootKeyID, rootPublic, tampered, signature, now, 0, ""); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("tampered keyset error = %v, want ErrInvalidKeyset", err)
	}
	if _, err := VerifyKeyset(keyset.RootKeyID, rootPublic, body, signature, now.Add(48*time.Hour), 0, ""); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("expired keyset error = %v, want ErrInvalidKeyset", err)
	}
	pretty := append([]byte(" "), body...)
	if _, err := VerifyKeyset(keyset.RootKeyID, rootPublic, pretty, signature, now, 0, ""); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("noncanonical keyset error = %v, want ErrInvalidKeyset", err)
	}
}

func TestKeysetRejectsDuplicateAndUnsortedKeys(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, keyset := keysetFixture(t, now)
	secondPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondEncoded, err := EncodePublicKey(secondPublic)
	if err != nil {
		t.Fatal(err)
	}
	second := KeysetEntry{
		ID: "aaa-secondary", PublicKey: string(bytesTrimLine(secondEncoded)),
		NotBefore: now.Add(-time.Hour).UTC().Format(time.RFC3339),
		NotAfter: now.Add(12*time.Hour).UTC().Format(time.RFC3339), Status: "active",
	}
	keyset.Keys = append(keyset.Keys, second)
	if _, err := EncodeCanonicalKeyset(keyset, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("unsorted keys error = %v, want ErrInvalidKeyset", err)
	}
	SortKeysetEntries(keyset.Keys)
	keyset.Keys[1].ID = keyset.Keys[0].ID
	if _, err := EncodeCanonicalKeyset(keyset, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("duplicate key ID error = %v, want ErrInvalidKeyset", err)
	}
	_ = rootPublic
	_ = rootPrivate
}

func TestManifestV2RequiresActiveKeysetAndRejectsRollback(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, keyset := keysetFixture(t, now)
	manifestPublic, manifestPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := EncodePublicKey(manifestPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyset.Keys[0].PublicKey = string(bytesTrimLine(encodedPublic))
	keysetBytes, keysetSignature := signKeyset(t, keyset, rootPrivate, now)
	verified, err := VerifyKeyset(keyset.RootKeyID, rootPublic, keysetBytes, keysetSignature, now, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	manifest := validManifest()
	manifest.Schema = ManifestSchemaV2
	manifest.SigningKeyID = keyset.Keys[0].ID
	manifest.KeysetEpoch = keyset.Epoch
	manifest.PublishedAt = now.Add(-30 * time.Minute).UTC().Format(time.RFC3339)
	body, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeSignature(ed25519.Sign(manifestPrivate, body))
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyManifestV2(verified, body, signature, now, "v1.2.2", 41)
	if err != nil {
		t.Fatal(err)
	}
	if got != manifest {
		t.Fatalf("verified manifest = %#v, want %#v", got, manifest)
	}
	if _, err := Verify(manifestPublic, body, signature); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("v1 verifier accepted v2 manifest: %v", err)
	}
	if _, err := VerifyManifestV2(verified, body, signature, now, "v1.2.3", 41); !errors.Is(err, ErrRollback) {
		t.Fatalf("version rollback error = %v, want ErrRollback", err)
	}
	if _, err := VerifyManifestV2(verified, body, signature, now, "v1.2.2", 42); !errors.Is(err, ErrRollback) {
		t.Fatalf("sequence rollback error = %v, want ErrRollback", err)
	}
	if _, err := VerifyManifestV2(verified, body, signature, now.Add(48*time.Hour), "v1.2.2", 41); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("expired keyset error = %v, want ErrInvalidKeyset", err)
	}
}

func TestManifestV2RejectsUnknownVerifyOnlyAndRevokedKeys(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rootPublic, rootPrivate, keyset := keysetFixture(t, now)
	manifestPublic, manifestPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := EncodePublicKey(manifestPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyset.Keys[0].PublicKey = string(bytesTrimLine(encodedPublic))
	manifest := validManifest()
	manifest.Schema = ManifestSchemaV2
	manifest.SigningKeyID = keyset.Keys[0].ID
	manifest.KeysetEpoch = keyset.Epoch
	manifest.PublishedAt = now.Add(-30 * time.Minute).UTC().Format(time.RFC3339)
	body, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeSignature(ed25519.Sign(manifestPrivate, body))
	if err != nil {
		t.Fatal(err)
	}

	verifyWithStatus := func(status, revokedAt string) error {
		t.Helper()
		keyset.Keys[0].Status = status
		keyset.Keys[0].RevokedAt = revokedAt
		keysetBytes, keysetSignature := signKeyset(t, keyset, rootPrivate, now)
		verified, err := VerifyKeyset(keyset.RootKeyID, rootPublic, keysetBytes, keysetSignature, now, 0, "")
		if err != nil {
			return err
		}
		_, err = VerifyManifestV2(verified, body, signature, now, "v1.2.2", 41)
		return err
	}
	if err := verifyWithStatus("verify-only", ""); !errors.Is(err, ErrUnknownSigningKey) {
		t.Fatalf("verify-only key error = %v, want ErrUnknownSigningKey", err)
	}
	if err := verifyWithStatus("revoked", now.Add(-time.Minute).UTC().Format(time.RFC3339)); !errors.Is(err, ErrRevokedSigningKey) {
		t.Fatalf("revoked key error = %v, want ErrRevokedSigningKey", err)
	}

	manifest.SigningKeyID = "unknown-key"
	unknownBody, err := EncodeCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	activeKeyset := keysetFixtureActive(t, now, rootPrivate, rootPublic)
	_, err = VerifyManifestV2(activeKeyset, unknownBody, signature, now, "v1.2.2", 41)
	if !errors.Is(err, ErrUnknownSigningKey) {
		t.Fatalf("unknown signing key error = %v, want ErrUnknownSigningKey", err)
	}
}

func keysetFixtureActive(t *testing.T, now time.Time, rootPrivate ed25519.PrivateKey, rootPublic ed25519.PublicKey) VerifiedKeyset {
	t.Helper()
	_, _, keyset := keysetFixture(t, now)
	body, signature := signKeyset(t, keyset, rootPrivate, now)
	verified, err := VerifyKeyset(keyset.RootKeyID, rootPublic, body, signature, now, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

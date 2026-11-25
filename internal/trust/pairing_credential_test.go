package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPairingCredentialVersionExpiryAndGeneration(t *testing.T) {
	dir := t.TempDir()
	first, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	record, err := readPairingCredentialRecord(dir)
	if err != nil {
		t.Fatal(err)
	}
	if record.Version != pairingCredentialVersion || record.Generation != 1 {
		t.Fatalf("unexpected credential: %+v", record)
	}
	if record.SecretSHA256 != HashSecret(first) || !record.ExpiresAt.After(record.IssuedAt) ||
		record.ExpiresAt.Sub(record.IssuedAt) > pairingCredentialLifetime {
		t.Fatalf("invalid credential lifetime: %+v", record)
	}
	second, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	record, err = readPairingCredentialRecord(dir)
	if err != nil {
		t.Fatal(err)
	}
	if record.Generation != 2 || record.SecretSHA256 != HashSecret(second) {
		t.Fatalf("generation did not advance: %+v", record)
	}
	if ok, err := CheckPairingSecret(dir, first); err != nil || ok {
		t.Fatalf("old credential accepted: ok=%v err=%v", ok, err)
	}
	if ok, err := CheckPairingSecret(dir, second); err != nil || !ok {
		t.Fatalf("new credential rejected: ok=%v err=%v", ok, err)
	}
}

func TestPairingCredentialRejectsExpiredAndFutureRecords(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name            string
		issued, expires time.Time
		want            error
	}{
		{name: "expired", issued: now.Add(-30 * time.Minute), expires: now.Add(-15 * time.Minute), want: ErrPairingSecretInvalid},
		{name: "future-issued", issued: now.Add(time.Minute), expires: now.Add(16 * time.Minute), want: ErrPairingStateUnsafe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			secret := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			hash := HashSecret(secret)
			if err := os.WriteFile(filepath.Join(dir, pairingSecretFile), []byte(hash+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			record := pairingCredentialRecord{Version: pairingCredentialVersion, Generation: 3, SecretSHA256: hash, IssuedAt: tc.issued, ExpiresAt: tc.expires}
			if err := writePairingCredential(dir, record); err != nil {
				t.Fatal(err)
			}
			_, err := loadPairingCredential(dir, hash, now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPairingCredentialRejectsMalformedAndUnknownVersion(t *testing.T) {
	for _, data := range []string{
		`{"version":99,"generation":1,"secret_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issued_at":"2026-11-24T00:00:00Z","expires_at":"2026-11-24T00:15:00Z"}`,
		`{"version":2,"generation":0,"secret_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issued_at":"2026-11-24T00:00:00Z","expires_at":"2026-11-24T00:15:00Z"}`,
		`{"version":2,"generation":1,"secret_sha256":"BAD","issued_at":"2026-11-24T00:00:00Z","expires_at":"2026-11-24T00:15:00Z","unexpected":true}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, pairingCredentialFile), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readPairingCredentialRecord(dir); !errors.Is(err, ErrPairingStateUnsafe) {
			t.Fatalf("malformed credential accepted: %v", err)
		}
	}
}

func TestLegacyPairingCredentialMigratesDurablyWithShortExpiry(t *testing.T) {
	dir := t.TempDir()
	secret := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hash := HashSecret(secret)
	path := filepath.Join(dir, pairingSecretFile)
	if err := os.WriteFile(path, []byte(hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record, err := loadPairingCredential(dir, hash, now)
	if err != nil {
		t.Fatal(err)
	}
	if record.Generation != 1 || record.SecretSHA256 != hash || record.IssuedAt != now || record.LastObservedAt != now ||
		record.ExpiresAt.Sub(now) > pairingCredentialLifetime {
		t.Fatalf("legacy migration not bounded: %+v", record)
	}
	persisted, err := readPairingCredentialRecord(dir)
	if err != nil || persisted != record {
		t.Fatalf("migration not durable: %+v %v", persisted, err)
	}
}

func TestLegacyPairingCredentialMigrationDeadlineIsEnforced(t *testing.T) {
	dir := t.TempDir()
	secret := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	hash := HashSecret(secret)
	if err := os.WriteFile(filepath.Join(dir, pairingSecretFile), []byte(hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadPairingCredential(dir, hash, pairingLegacyMigrationDeadline.Add(time.Second))
	if !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("legacy credential survived migration deadline: %v", err)
	}
}

func TestPairingCredentialAdmissionReceivesGenerationBeforeConsumption(t *testing.T) {
	dir := t.TempDir()
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(dir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = PairClientWithSecretAdmission(dir, secret, store, pairingTestPeer("wd_cccccccccccccccc"), func(generation uint64) error {
		called = true
		if generation != 1 {
			t.Fatalf("credential generation=%d, want 1", generation)
		}
		if hash, checkErr := readPairingHash(filepath.Join(dir, pairingSecretFile)); checkErr != nil || hash != HashSecret(secret) {
			t.Fatalf("secret consumed before admission: %q %v", hash, checkErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("generation admission callback was not invoked")
	}
	if ok, err := CheckPairingSecret(dir, secret); err != nil || ok {
		t.Fatalf("consumed secret remained valid: %v %v", ok, err)
	}
	consumed, err := readPairingCredentialRecord(dir)
	if err != nil || !consumed.Consumed {
		t.Fatalf("credential metadata not marked consumed: %+v %v", consumed, err)
	}
}

func TestPairingCredentialRotationRecoversInterruptedConsumptionMetadata(t *testing.T) {
	dir := t.TempDir()
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	record, err := readPairingCredentialRecord(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, pairingSecretFile), []byte(consumedPairingHash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatalf("rotation did not reconcile durable tombstone: %v", err)
	}
	if rotated == secret {
		t.Fatal("rotation reused the consumed secret")
	}
	next, err := readPairingCredentialRecord(dir)
	if err != nil {
		t.Fatal(err)
	}
	if next.Generation != record.Generation+1 || next.SecretSHA256 != HashSecret(rotated) || next.Consumed {
		t.Fatalf("interrupted consumption recovery produced invalid generation: %+v", next)
	}
}

func TestWrongSecretCannotTriggerLegacyCredentialMigration(t *testing.T) {
	dir := t.TempDir()
	secret := "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	if err := os.WriteFile(filepath.Join(dir, pairingSecretFile), []byte(HashSecret(secret)+"\n"), 0o600); err != nil { t.Fatal(err) }
	if ok, err := CheckPairingSecret(dir, "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"); err != nil || ok {
		t.Fatalf("wrong legacy secret accepted: %v %v", ok, err)
	}
	if _, err := os.Stat(filepath.Join(dir, pairingCredentialFile)); !os.IsNotExist(err) {
		t.Fatalf("wrong secret triggered legacy migration: %v", err)
	}
	if ok, err := CheckPairingSecret(dir, secret); err != nil || !ok {
		t.Fatalf("valid legacy secret failed migration: %v %v", ok, err)
	}
	if _, err := os.Stat(filepath.Join(dir, pairingCredentialFile)); err != nil { t.Fatalf("valid secret did not persist migration: %v", err) }
}


func TestPairingCredentialRejectsClockRollbackAndPersistsHighWaterMark(t *testing.T) {
	dir := t.TempDir()
	secret, err := RotatePairingSecret(dir)
	if err != nil { t.Fatal(err) }
	hash := HashSecret(secret)
	record, err := readPairingCredentialRecord(dir)
	if err != nil { t.Fatal(err) }
	advanced := record.IssuedAt.Add(2 * time.Minute)
	record.LastObservedAt = advanced
	if err := writePairingCredential(dir, record); err != nil { t.Fatal(err) }

	_, err = loadPairingCredential(dir, hash, advanced.Add(-time.Minute))
	if !errors.Is(err, ErrPairingStateUnsafe) {
		t.Fatalf("clock rollback was not rejected: %v", err)
	}
	accepted, err := loadPairingCredential(dir, hash, advanced.Add(-10*time.Second))
	if err != nil { t.Fatalf("small clock skew within tolerance rejected: %v", err) }
	if !accepted.LastObservedAt.Equal(advanced) {
		t.Fatalf("clock high-water mark moved backwards: %s", accepted.LastObservedAt)
	}
	accepted, err = loadPairingCredential(dir, hash, advanced.Add(time.Minute))
	if err != nil { t.Fatal(err) }
	if !accepted.LastObservedAt.Equal(advanced.Add(time.Minute)) {
		t.Fatalf("new clock high-water mark not persisted: %s", accepted.LastObservedAt)
	}
	persisted, err := readPairingCredentialRecord(dir)
	if err != nil { t.Fatal(err) }
	if !persisted.LastObservedAt.Equal(advanced.Add(time.Minute)) {
		t.Fatalf("persisted clock high-water mark mismatch: %s", persisted.LastObservedAt)
	}
}

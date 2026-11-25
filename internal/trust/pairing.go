package trust

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	pairingSecretFile         = "pairing-secret.sha256"
	pairingCredentialFile     = "pairing-credential.json"
	pairingCredentialVersion  = 2
	pairingCredentialLifetime = 15 * time.Minute
	pairingHashBytes          = 65 // 64 lowercase SHA-256 hex characters and LF.
	consumedPairingHash       = "0000000000000000000000000000000000000000000000000000000000000000"
)

var pairingLegacyMigrationDeadline = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

var (
	ErrPairingSecretInvalid  = errors.New("pairing secret is invalid, missing, or already consumed")
	ErrPairingStateUnsafe    = errors.New("pairing state is unavailable or unsafe")
	ErrPairingTrustPersist   = errors.New("pairing secret consumed but trust persistence failed")
	ErrPairingTrustUncertain = errors.New("pairing trust persistence outcome could not be verified")
)

// PairClientWithSecret is the only pairing authorization transaction. A
// persisted consumed marker is synced before any trust insertion.
func PairClientWithSecret(dir, secret string, clients *Store, peer Peer) error {
	return pairClientWithHooks(dir, secret, clients, peer, pairingHooks{})
}

// PairClientWithSecretAdmission reserves the credential generation while the
// cross-process credential lock is held, before the one-time marker is synced.
func PairClientWithSecretAdmission(dir, secret string, clients *Store, peer Peer, admit func(uint64) error) error {
	return pairClientWithHooks(dir, secret, clients, peer, pairingHooks{admit: admit})
}

// Test-only hooks are passed per transaction, never stored in shared globals.
type pairingCredentialRecord struct {
	Version      int       `json:"version"`
	Generation   uint64    `json:"generation"`
	SecretSHA256 string    `json:"secret_sha256"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastObservedAt time.Time `json:"last_observed_at,omitempty"`
	Consumed     bool      `json:"consumed,omitempty"`
}

type pairingHooks struct {
	admit          func(uint64) error
	beforeAcquire  func()
	beforeConsume  func()
	afterConsume   func() error
	putTrust       func(Peer) error
	reconcileTrust func(Peer) (bool, error)
}

func pairClientWithHooks(dir, secret string, clients *Store, peer Peer, hooks pairingHooks) error {
	if clients == nil {
		return fmt.Errorf("%w: terminal trust store is unavailable", ErrPairingStateUnsafe)
	}
	if filepath.Clean(clients.path) != filepath.Join(filepath.Clean(dir), "trusted-clients.json") {
		return fmt.Errorf("%w: pairing requires the dedicated terminal trust store", ErrPairingStateUnsafe)
	}
	if !validPairingSecret(secret) {
		return ErrPairingSecretInvalid
	}
	if hooks.beforeAcquire != nil {
		hooks.beforeAcquire()
	}
	path, unlock, err := lockPairing(dir)
	if err != nil {
		return err
	}
	defer unlock()

	hash, err := readPairingHash(path)
	if err != nil {
		return err
	}
	credential, err := loadPairingCredential(dir, hash, time.Now().UTC())
	if err != nil {
		return err
	}
	if !SecretMatches(credential.SecretSHA256, secret) {
		return ErrPairingSecretInvalid
	}
	if hooks.admit != nil {
		if err := hooks.admit(credential.Generation); err != nil {
			return err
		}
	}
	if hooks.beforeConsume != nil {
		hooks.beforeConsume()
	}
	if err := consumePairingSecretFile(path, hash); err != nil {
		return err
	}
	credential.Consumed = true
	if err := writePairingCredential(dir, credential); err != nil {
		return fmt.Errorf("%w: consumed credential metadata: %v", ErrPairingStateUnsafe, err)
	}
	if hooks.afterConsume != nil {
		if err := hooks.afterConsume(); err != nil {
			return fmt.Errorf("%w: after durable consumption: %v", ErrPairingStateUnsafe, err)
		}
	}
	put := clients.PutPairing
	if hooks.putTrust != nil {
		put = hooks.putTrust
	}
	if err := put(peer); err != nil {
		// A visible record never proves directory-sync durability. Only an
		// explicit post-sync indication from Store can reconcile an error.
		reconcile := clients.pairingPeerOnDisk
		if hooks.reconcileTrust != nil {
			reconcile = hooks.reconcileTrust
		}
		persisted, checkErr := reconcile(peer)
		if checkErr != nil {
			return fmt.Errorf("%w: write: %v; verify: %v", ErrPairingTrustUncertain, err, checkErr)
		}
		if errors.Is(err, errTrustStoreCommitted) {
			if persisted {
				return &pairingReconciledError{cause: err}
			}
			return fmt.Errorf("%w: confirmed trust record is missing: %v", ErrPairingTrustUncertain, err)
		}
		if persisted || errors.Is(err, ErrTrustStoreDurability) {
			return fmt.Errorf("%w: trust commit not confirmed durable: %v", ErrPairingTrustUncertain, err)
		}
		return fmt.Errorf("%w: %v", ErrPairingTrustPersist, err)
	}
	return nil
}

// VerifyPairingStatePath enforces private ownership, narrow Windows ACLs,
// and stable real-file identities for the pairing recovery register.
func VerifyPairingStatePath(path string) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || (!before.IsDir() && !before.Mode().IsRegular()) {
		return errors.New("pairing recovery path has an unsafe type")
	}
	if !pairingOwnedByCurrentUser(before) {
		return errors.New("pairing recovery state has foreign ownership")
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return errors.New("pairing recovery state has broad permissions")
	}
	if err := pairingWindowsStateSecure(path); err != nil {
		return fmt.Errorf("pairing recovery Windows ACL: %w", err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("pairing recovery path changed during verification")
	}
	return nil
}

// RotatePairingSecret synchronizes with every consumer and installs a complete
// 0600 hash through an atomic same-directory replacement. The plaintext secret
// is never persisted. Unsafe existing state is not silently overwritten.
func RotatePairingSecret(dir string) (string, error) {
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf[:])
	path, unlock, err := lockPairing(dir)
	if err != nil {
		return "", err
	}
	defer unlock()

	oldHash, hashErr := readPairingHash(path)
	if hashErr != nil && !errors.Is(hashErr, ErrPairingSecretInvalid) {
		return "", hashErr
	}
	previousGeneration := uint64(0)
	oldRecord, recordErr := readPairingCredentialRecord(dir)
	if recordErr != nil && !errors.Is(recordErr, os.ErrNotExist) {
		return "", recordErr
	}
	if recordErr == nil {
		if oldHash != "" && oldRecord.SecretSHA256 != oldHash {
			return "", fmt.Errorf("%w: credential hash and metadata disagree", ErrPairingStateUnsafe)
		}
		if oldHash == "" && !oldRecord.Consumed {
			legacyTombstone, readErr := os.ReadFile(path)
			if readErr != nil || string(legacyTombstone) != consumedPairingHash+"\n" {
				return "", fmt.Errorf("%w: active credential metadata has no matching hash", ErrPairingStateUnsafe)
			}
			// Recover a crash after the durable hash tombstone but before the
			// credential metadata's consumed marker was synchronized.
			oldRecord.Consumed = true
			if err := writePairingCredential(dir, oldRecord); err != nil {
				return "", fmt.Errorf("%w: reconcile interrupted credential consumption: %v", ErrPairingStateUnsafe, err)
			}
		}
		previousGeneration = oldRecord.Generation
	} else if hashErr == nil || errors.Is(hashErr, ErrPairingSecretInvalid) {
		if _, statErr := os.Lstat(path); statErr == nil {
			previousGeneration = 1
		}
	}
	if previousGeneration == ^uint64(0) {
		return "", fmt.Errorf("%w: credential generation exhausted", ErrPairingStateUnsafe)
	}
	now := time.Now().UTC()
	if recordErr == nil {
		lastObserved := oldRecord.LastObservedAt
		if lastObserved.IsZero() { lastObserved = oldRecord.IssuedAt }
		if now.Add(30 * time.Second).Before(lastObserved) {
			return "", fmt.Errorf("%w: system clock moved backwards", ErrPairingStateUnsafe)
		}
		if now.After(lastObserved) {
			oldRecord.LastObservedAt = now
			if err := writePairingCredential(dir, oldRecord); err != nil { return "", fmt.Errorf("%w: persist trusted clock observation: %v", ErrPairingStateUnsafe, err) }
		}
	}
	record := pairingCredentialRecord{Version: pairingCredentialVersion, Generation: previousGeneration + 1,
		SecretSHA256: HashSecret(secret), IssuedAt: now, ExpiresAt: now.Add(pairingCredentialLifetime), LastObservedAt: now}

	if err := writePairingHash(path, record.SecretSHA256); err != nil {
		return "", err
	}
	if err := writePairingCredential(dir, record); err != nil {
		return "", fmt.Errorf("%w: credential metadata rotation uncertain: %v", ErrPairingStateUnsafe, err)
	}
	return secret, nil
}

func writePairingHash(path, hash string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pairing-secret-*")
	if err != nil {
		return fmt.Errorf("%w: create replacement: %v", ErrPairingStateUnsafe, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	fail := func(err error) error { _ = tmp.Close(); return fmt.Errorf("%w: %v", ErrPairingStateUnsafe, err) }
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := pairingWindowsStateSecure(name); err != nil {
		return fail(err)
	}
	if _, err := io.WriteString(tmp, hash+"\n"); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: close replacement: %v", ErrPairingStateUnsafe, err)
	}
	if err := replaceStoreFile(name, path); err != nil {
		return fmt.Errorf("%w: replace secret: %v", ErrPairingStateUnsafe, err)
	}
	if err := syncPairingDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%w: synchronize rotated hash directory: %v", ErrPairingStateUnsafe, err)
	}
	return nil
}

func readPairingCredentialRecord(dir string) (pairingCredentialRecord, error) {
	var record pairingCredentialRecord
	path := filepath.Join(dir, pairingCredentialFile)
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
		return record, fmt.Errorf("%w: credential metadata type or size invalid", ErrPairingStateUnsafe)
	}
	if err := pairingWindowsStateSecure(path); err != nil {
		return record, fmt.Errorf("%w: credential metadata ACL: %v", ErrPairingStateUnsafe, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return record, fmt.Errorf("%w: credential metadata permissions unsafe", ErrPairingStateUnsafe)
	}
	f, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer f.Close()
	opened, err := f.Stat()
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(info, opened) || !os.SameFile(opened, after) {
		return record, fmt.Errorf("%w: credential metadata changed during read", ErrPairingStateUnsafe)
	}
	decoder := json.NewDecoder(io.LimitReader(f, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("%w: malformed credential metadata: %v", ErrPairingStateUnsafe, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return record, fmt.Errorf("%w: credential metadata trailing data", ErrPairingStateUnsafe)
	}
	if record.Version != pairingCredentialVersion || record.Generation == 0 || len(record.SecretSHA256) != 64 ||
		record.IssuedAt.IsZero() || record.ExpiresAt.IsZero() || !record.ExpiresAt.After(record.IssuedAt) ||
		record.ExpiresAt.Sub(record.IssuedAt) > pairingCredentialLifetime {
		return record, fmt.Errorf("%w: invalid credential metadata fields", ErrPairingStateUnsafe)
	}
	digest, decodeErr := hex.DecodeString(record.SecretSHA256)
	if decodeErr != nil || len(digest) != 32 || strings.ToLower(record.SecretSHA256) != record.SecretSHA256 {
		return record, fmt.Errorf("%w: invalid credential digest", ErrPairingStateUnsafe)
	}
	if record.IssuedAt.After(time.Now().UTC().Add(30 * time.Second)) {
		return record, fmt.Errorf("%w: credential issue time is in the future", ErrPairingStateUnsafe)
	}
	return record, nil
}

func writePairingCredential(dir string, record pairingCredentialRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > 4096 {
		return errors.New("credential metadata size invalid")
	}
	path := filepath.Join(dir, pairingCredentialFile)
	tmp, err := os.CreateTemp(dir, ".pairing-credential-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	fail := func(err error) error { _ = tmp.Close(); return err }
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := pairingWindowsStateSecure(name); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceStoreFile(name, path); err != nil {
		return err
	}
	if err := syncPairingDirectory(dir); err != nil {
		return err
	}
	return nil
}

func loadPairingCredential(dir, hash string, now time.Time) (pairingCredentialRecord, error) {
	record, err := readPairingCredentialRecord(dir)
	if errors.Is(err, os.ErrNotExist) {
		if hash == "" || hash == consumedPairingHash {
			return record, ErrPairingSecretInvalid
		}
		if !now.Before(pairingLegacyMigrationDeadline) {
			return record, ErrPairingSecretInvalid
		}
		info, statErr := os.Lstat(filepath.Join(dir, pairingSecretFile))
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !pairingOwnedByCurrentUser(info) {
			return record, fmt.Errorf("%w: inspect legacy credential: %v", ErrPairingStateUnsafe, statErr)
		}
		if info.ModTime().After(now.Add(30 * time.Second)) {
			return record, fmt.Errorf("%w: legacy credential is future-dated", ErrPairingStateUnsafe)
		}
		expires := now.Add(pairingCredentialLifetime)
		if expires.After(pairingLegacyMigrationDeadline) {
			expires = pairingLegacyMigrationDeadline
		}
		record = pairingCredentialRecord{Version: pairingCredentialVersion, Generation: 1, SecretSHA256: hash, IssuedAt: now, ExpiresAt: expires, LastObservedAt: now}
		if err := writePairingCredential(dir, record); err != nil {
			return record, fmt.Errorf("%w: migrate legacy credential: %v", ErrPairingStateUnsafe, err)
		}
		return record, nil
	}
	if err != nil {
		return record, err
	}
	if record.Consumed || record.SecretSHA256 != hash {
		return record, ErrPairingSecretInvalid
	}
	if record.IssuedAt.After(now.Add(30 * time.Second)) {
		return record, fmt.Errorf("%w: credential issue time is in the future", ErrPairingStateUnsafe)
	}
	lastObserved := record.LastObservedAt
	if lastObserved.IsZero() { lastObserved = record.IssuedAt }
	if now.Add(30 * time.Second).Before(lastObserved) {
		return record, fmt.Errorf("%w: system clock moved backwards", ErrPairingStateUnsafe)
	}
	if !now.Before(record.ExpiresAt) {
		return record, ErrPairingSecretInvalid
	}
	if now.After(lastObserved) {
		record.LastObservedAt = now
		if err := writePairingCredential(dir, record); err != nil {
			return record, fmt.Errorf("%w: persist trusted clock observation: %v", ErrPairingStateUnsafe, err)
		}
	}
	return record, nil
}

// CheckPairingSecret validates the credential under the pairing lock. A legacy
// V1 hash may be durably migrated here; callers must never authorize pairing
// from this preflight alone. PairClientWithSecretAdmission revalidates and consumes.
func CheckPairingSecret(dir, secret string) (bool, error) {
	if !validPairingSecret(secret) {
		return false, nil
	}
	path, unlock, err := lockPairing(dir)
	if err != nil {
		return false, err
	}
	defer unlock()
	hash, err := readPairingHash(path)
	if errors.Is(err, ErrPairingSecretInvalid) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	credential, err := loadPairingCredential(dir, hash, time.Now().UTC())
	if errors.Is(err, ErrPairingSecretInvalid) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return SecretMatches(credential.SecretSHA256, secret), nil
}

func validPairingSecret(secret string) bool {
	if len(secret) != 32 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	return err == nil && len(raw) == 24 && base64.RawURLEncoding.EncodeToString(raw) == secret
}

func lockPairing(dir string) (string, func(), error) {
	if dir == "" {
		return "", nil, fmt.Errorf("%w: state directory is empty", ErrPairingStateUnsafe)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("%w: create state directory: %v", ErrPairingStateUnsafe, err)
	}
	before, err := os.Lstat(dir)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return "", nil, fmt.Errorf("%w: state directory is not a real directory", ErrPairingStateUnsafe)
	}
	if !pairingOwnedByCurrentUser(before) {
		return "", nil, fmt.Errorf("%w: state directory is not owned by this process", ErrPairingStateUnsafe)
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		// On Unix the process may repair its own state directory, but must
		// change permissions on a verified descriptor, never a swapped path.
		f, openErr := os.Open(dir)
		if openErr != nil {
			return "", nil, fmt.Errorf("%w: open state directory: %v", ErrPairingStateUnsafe, openErr)
		}
		opened, statErr := f.Stat()
		onPath, pathErr := os.Lstat(dir)
		if statErr != nil || pathErr != nil || !opened.IsDir() || !os.SameFile(before, opened) ||
			!os.SameFile(opened, onPath) {
			_ = f.Close()
			return "", nil, fmt.Errorf("%w: state directory changed before securing", ErrPairingStateUnsafe)
		}
		chmodErr := f.Chmod(0o700)
		closeErr := f.Close()
		if chmodErr != nil || closeErr != nil {
			return "", nil, fmt.Errorf("%w: cannot secure state directory", ErrPairingStateUnsafe)
		}
	}
	if err := pairingWindowsStateSecure(dir); err != nil {
		return "", nil, fmt.Errorf("%w: state directory ACL: %v", ErrPairingStateUnsafe, err)
	}
	// Check filesystem durability support before reading, consuming or
	// rotating a secret, including hashes provisioned by older versions.
	if err := syncPairingDirectory(dir); err != nil {
		return "", nil, fmt.Errorf("%w: state filesystem durability: %v", ErrPairingStateUnsafe, err)
	}
	path := filepath.Join(dir, pairingSecretFile)
	unlock, err := lockPairingFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("%w: acquire pairing lock: %v", ErrPairingStateUnsafe, err)
	}
	after, err := os.Lstat(dir)
	if err != nil || !os.SameFile(before, after) || after.Mode()&os.ModeSymlink != 0 {
		unlock()
		return "", nil, fmt.Errorf("%w: state directory changed during lock", ErrPairingStateUnsafe)
	}
	return path, unlock, nil
}

// An absent hash is a cleanly rejected replay, while unexpected files, loose
// Unix modes, invalid encodings, and path changes are operational failures.
func readPairingHash(path string) (string, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrPairingSecretInvalid
	}
	if err != nil {
		return "", fmt.Errorf("%w: stat hash: %v", ErrPairingStateUnsafe, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != pairingHashBytes {
		return "", fmt.Errorf("%w: hash file type or size invalid", ErrPairingStateUnsafe)
	}
	if !pairingOwnedByCurrentUser(before) {
		return "", fmt.Errorf("%w: hash file ownership is unsafe", ErrPairingStateUnsafe)
	}
	if err := pairingWindowsStateSecure(path); err != nil {
		return "", fmt.Errorf("%w: hash file ACL: %v", ErrPairingStateUnsafe, err)
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%w: hash file permissions are unsafe", ErrPairingStateUnsafe)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%w: open hash: %v", ErrPairingStateUnsafe, err)
	}
	defer f.Close()
	opened, e1 := f.Stat()
	after, e2 := os.Lstat(path)
	if e1 != nil || e2 != nil || !opened.Mode().IsRegular() || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return "", fmt.Errorf("%w: hash path changed during read", ErrPairingStateUnsafe)
	}
	data, err := io.ReadAll(io.LimitReader(f, pairingHashBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: read hash: %v", ErrPairingStateUnsafe, err)
	}
	if len(data) != pairingHashBytes || data[64] != '\n' {
		return "", fmt.Errorf("%w: invalid hash encoding", ErrPairingStateUnsafe)
	}
	hash := string(data[:64])
	if _, err := hex.DecodeString(hash); err != nil || strings.ToLower(hash) != hash {
		return "", fmt.Errorf("%w: malformed hash", ErrPairingStateUnsafe)
	}
	if hash == consumedPairingHash {
		return "", ErrPairingSecretInvalid
	}
	return hash, nil
}

// A 65-byte tombstone overwrites the existing inode, avoiding a directory
// removal transaction whose metadata might roll back after sudden power loss.
// FlushFileBuffers/fsync must succeed before trust is ever written.
func consumePairingSecretFile(path, expectedHash string) error {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() != pairingHashBytes {
		return fmt.Errorf("%w: hash file disappeared before consumption", ErrPairingStateUnsafe)
	}
	if err := pairingWindowsStateSecure(path); err != nil {
		return fmt.Errorf("%w: hash file ACL: %v", ErrPairingStateUnsafe, err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("%w: open hash for consumption: %v", ErrPairingStateUnsafe, err)
	}
	defer f.Close()
	opened, e1 := f.Stat()
	onPath, e2 := os.Lstat(path)
	if e1 != nil || e2 != nil || onPath.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(opened, onPath) {
		return fmt.Errorf("%w: hash path changed before consumption", ErrPairingStateUnsafe)
	}
	var data [pairingHashBytes]byte
	if _, err := f.ReadAt(data[:], 0); err != nil || string(data[:]) != expectedHash+"\n" {
		return ErrPairingSecretInvalid
	}
	tombstone := []byte(consumedPairingHash + "\n")
	if n, err := f.WriteAt(tombstone, 0); err != nil || n != len(tombstone) {
		return fmt.Errorf("%w: write consumed marker: %v", ErrPairingStateUnsafe, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("%w: durable consumed marker: %v", ErrPairingStateUnsafe, err)
	}
	if _, err := f.ReadAt(data[:], 0); err != nil || string(data[:]) != string(tombstone) {
		return fmt.Errorf("%w: verify consumed marker", ErrPairingStateUnsafe)
	}
	onPath, err = os.Lstat(path)
	if err != nil || onPath.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, onPath) {
		return fmt.Errorf("%w: consumed file identity changed", ErrPairingStateUnsafe)
	}
	return nil
}

// Reconciliation is an explicit, successful-on-disk result, not a generic
// persistence failure: the caller must emit an attributable audit event.
type pairingReconciledError struct{ cause error }

func (e *pairingReconciledError) Error() string {
	return "pairing trust persisted after write error: " + e.cause.Error()
}
func (e *pairingReconciledError) Unwrap() error { return e.cause }
func IsPairingReconciled(err error) bool {
	var reconciled *pairingReconciledError
	return errors.As(err, &reconciled)
}

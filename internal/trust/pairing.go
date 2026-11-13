package trust

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	pairingSecretFile   = "pairing-secret.sha256"
	pairingHashBytes    = 65 // 64 lowercase SHA-256 hex characters and LF.
	consumedPairingHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

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

// Test-only hooks are passed per transaction, never stored in shared globals.
type pairingHooks struct {
	beforeConsume func()
	afterConsume  func() error
	putTrust      func(Peer) error
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
	path, unlock, err := lockPairing(dir)
	if err != nil {
		return err
	}
	defer unlock()

	hash, err := readPairingHash(path)
	if err != nil {
		return err
	}
	if !SecretMatches(hash, secret) {
		return ErrPairingSecretInvalid
	}
	if hooks.beforeConsume != nil {
		hooks.beforeConsume()
	}
	if err := consumePairingSecretFile(path, hash); err != nil {
		return err
	}
	if hooks.afterConsume != nil {
		if err := hooks.afterConsume(); err != nil {
			return fmt.Errorf("%w: after durable consumption: %v", ErrPairingStateUnsafe, err)
		}
	}
	put := clients.Put
	if hooks.putTrust != nil {
		put = hooks.putTrust
	}
	if err := put(peer); err != nil {
		// A trust writer may return an error after the new file became visible.
		// Never report a definite failure if this exact identity is on disk.
		persisted, checkErr := clients.pairingPeerOnDisk(peer)
		if checkErr != nil {
			return fmt.Errorf("%w: write: %v; verify: %v", ErrPairingTrustUncertain, err, checkErr)
		}
		if persisted {
			if errors.Is(err, ErrTrustStoreDurability) {
				return fmt.Errorf("%w: trust snapshot is visible but not durably synchronized: %v", ErrPairingTrustUncertain, err)
			}
			return &pairingReconciledError{cause: err}
		}
		return fmt.Errorf("%w: %v", ErrPairingTrustPersist, err)
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

	if _, err := readPairingHash(path); err != nil && !errors.Is(err, ErrPairingSecretInvalid) {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pairing-secret-*")
	if err != nil {
		return "", fmt.Errorf("%w: create replacement: %v", ErrPairingStateUnsafe, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	closeWithError := func(err error) (string, error) {
		_ = tmp.Close()
		return "", fmt.Errorf("%w: %v", ErrPairingStateUnsafe, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return closeWithError(err)
	}
	if err := pairingWindowsStateSecure(tmpPath); err != nil {
		return closeWithError(err)
	}
	if _, err := io.WriteString(tmp, HashSecret(secret)+"\n"); err != nil {
		return closeWithError(err)
	}
	if err := tmp.Sync(); err != nil {
		return closeWithError(err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("%w: close replacement: %v", ErrPairingStateUnsafe, err)
	}
	// Defend against substitution between inspection and replacement.
	if _, err := readPairingHash(path); err != nil && !errors.Is(err, ErrPairingSecretInvalid) {
		return "", err
	}
	if err := replacePairingSecretFile(tmpPath, path); err != nil {
		return "", fmt.Errorf("%w: replace secret: %v", ErrPairingStateUnsafe, err)
	}
	if err := syncPairingDirectory(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("%w: synchronize rotated hash directory: %v", ErrPairingStateUnsafe, err)
	}
	hash, err := readPairingHash(path)
	if err != nil || !SecretMatches(hash, secret) {
		return "", fmt.Errorf("%w: verify rotated secret", ErrPairingStateUnsafe)
	}
	return secret, nil
}

// CheckPairingSecret is read-only; callers must never authorize pairing using
// this check. PairClientWithSecret performs the locked consume+trust transaction.
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
	return SecretMatches(hash, secret), nil
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

func (e *pairingReconciledError) Error() string { return "pairing trust persisted after write error: " + e.cause.Error() }
func (e *pairingReconciledError) Unwrap() error { return e.cause }
func IsPairingReconciled(err error) bool {
	var reconciled *pairingReconciledError
	return errors.As(err, &reconciled)
}

package trust

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Peer struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	Endpoint    string    `json:"endpoint,omitempty"`
	TrustedAt   time.Time `json:"trusted_at"`
}

const maxStoreSize = 1 << 20

// ErrTrustStoreDurability means pairing cannot prove that an attempted
// replacement is durable, even when the new snapshot is readable on disk.
var ErrTrustStoreDurability = errors.New("trust store namespace durability uncertain")

// This private marker can be produced only after the pairing directory sync.
// A readable snapshot on its own never establishes durability.
var errTrustStoreCommitted = errors.New("pairing trust store durably committed")

// Optional per-store fault hooks are unused outside package tests.
type pairingCommitHooks struct {
	beforeReplace func() error
	afterReplace  func() error
	syncDirectory func(string) error
	afterCommit   func() error
}

type Store struct {
	mu          sync.Mutex
	path        string
	Peers       map[string]Peer `json:"peers"`
	commitHooks pairingCommitHooks
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, Peers: map[string]Peer{}}
	if err := s.reloadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Get(id string) (Peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reloadLocked() != nil {
		return Peer{}, false
	}
	p, ok := s.Peers[id]
	return p, ok
}

func (s *Store) FindByFingerprint(fp string) (Peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reloadLocked() != nil {
		return Peer{}, false
	}
	for _, p := range s.Peers {
		if p.Fingerprint == fp {
			return p, true
		}
	}
	return Peer{}, false
}

func (s *Store) Put(p Peer) error {
	return s.put(p, false)
}

// PutPairing requires durable directory metadata before acknowledging a
// newly trusted terminal client. Other trust domains retain their existing
// storage policy, rather than inheriting pairing-specific filesystem gates.
func (s *Store) PutPairing(p Peer) error {
	return s.put(p, true)
}

func (s *Store) put(p Peer, pairingDurable bool) error {
	unlock, err := lockStoreFile(s.path)
	if err != nil {
		return err
	}
	defer unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadLocked(); err != nil {
		return err
	}
	if p.TrustedAt.IsZero() {
		p.TrustedAt = time.Now().UTC()
	}
	previous, existed := s.Peers[p.ID]
	s.Peers[p.ID] = p
	if err := s.saveLocked(pairingDurable); err != nil {
		if existed {
			s.Peers[p.ID] = previous
		} else {
			delete(s.Peers, p.ID)
		}
		return err
	}
	return nil
}

func (s *Store) List() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reloadLocked() != nil {
		return nil
	}
	out := make([]Peer, 0, len(s.Peers))
	for _, p := range s.Peers {
		out = append(out, p)
	}
	return out
}

func (s *Store) Delete(id string) (bool, error) {
	_, deleted, err := s.DeletePeer(id)
	return deleted, err
}

func (s *Store) DeletePeer(id string) (Peer, bool, error) {
	unlock, err := lockStoreFile(s.path)
	if err != nil {
		return Peer{}, false, err
	}
	defer unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadLocked(); err != nil {
		return Peer{}, false, err
	}
	peer, ok := s.Peers[id]
	if !ok {
		return Peer{}, false, nil
	}
	delete(s.Peers, id)
	if err := s.saveLocked(false); err != nil {
		s.Peers[id] = peer
		return Peer{}, false, err
	}
	return peer, true, nil
}

func (s *Store) reloadLocked() error {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.Peers = map[string]Peer{}
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("trust store must not be a symbolic link")
	}
	if info.Size() <= 0 || info.Size() > maxStoreSize {
		return errors.New("trust store has an invalid size")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("secure trust store permissions: %w", err)
	}
	var snapshot struct {
		Peers map[string]Peer `json:"peers"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("parse trust store: %w", err)
	}
	if snapshot.Peers == nil {
		snapshot.Peers = map[string]Peer{}
	}
	s.Peers = snapshot.Peers
	return nil
}

func (s *Store) saveLocked(pairingDurable bool) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxStoreSize {
		return errors.New("trust store has an invalid size")
	}
	tmp, err := os.CreateTemp(dir, ".trusted-devices-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if pairingDurable && s.commitHooks.beforeReplace != nil {
		if err := s.commitHooks.beforeReplace(); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
	}
	if err := replaceStoreFile(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		if pairingDurable {
			// An API error cannot prove the original snapshot is still intact.
			return fmt.Errorf("%w: replacement: %v", ErrTrustStoreDurability, err)
		}
		return err
	}
	if !pairingDurable {
		// Unrelated trust domains retain their existing persistence contract.
		return os.Chmod(s.path, 0o600)
	}
	// The replacement was already secured (0600) and its contents synced.
	// No fallible permissions mutation is allowed before durability.
	if s.commitHooks.afterReplace != nil {
		if err := s.commitHooks.afterReplace(); err != nil {
			return fmt.Errorf("%w: after replacement: %v", ErrTrustStoreDurability, err)
		}
	}
	syncDirectory := syncPairingDirectory
	if s.commitHooks.syncDirectory != nil {
		syncDirectory = s.commitHooks.syncDirectory
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("%w: directory sync: %v", ErrTrustStoreDurability, err)
	}
	// Only errors beyond this point are eligible for positive reconciliation.
	if s.commitHooks.afterCommit != nil {
		if err := s.commitHooks.afterCommit(); err != nil {
			return fmt.Errorf("%w: %v", errTrustStoreCommitted, err)
		}
	}
	return nil
}

// pairingPeerOnDisk bypasses the in-memory snapshot after a failed write.
// It distinguishes an unreadable/ambiguous commit from a definitively absent
// identity, and never accepts a different fingerprint as the same peer.
func (s *Store) pairingPeerOnDisk(peer Peer) (bool, error) {
	if s == nil {
		return false, errors.New("trust store is nil")
	}
	fresh, err := Open(s.path)
	if err != nil {
		return false, err
	}
	stored, exists := fresh.Peers[peer.ID]
	if !exists {
		return false, nil
	}
	if stored.Fingerprint != peer.Fingerprint {
		return false, errors.New("trust store has a conflicting identity")
	}
	return true, nil
}

func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func SecretMatches(storedHash, secret string) bool {
	want, err1 := hex.DecodeString(storedHash)
	gotHash := sha256.Sum256([]byte(secret))
	if err1 != nil || len(want) != len(gotHash) {
		return false
	}
	return subtle.ConstantTimeCompare(want, gotHash[:]) == 1
}

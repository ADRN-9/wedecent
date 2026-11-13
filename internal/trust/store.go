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

// ErrTrustStoreDurability means a replacement was visible, but syncing its
// directory failed, so a crash could still lose the new namespace entry.
var ErrTrustStoreDurability = errors.New("trust store namespace durability uncertain")

type Store struct {
	mu    sync.Mutex
	path  string
	Peers map[string]Peer `json:"peers"`
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
	if err := s.saveLocked(); err != nil {
		if existed {
			s.Peers[p.ID] = previous
		} else {
			delete(s.Peers, p.ID)
		}
		return err
	}
	if pairingDurable {
		// This occurs only after a successful atomic replacement. A failure
		// here is post-commit uncertainty, never an absent/failed insertion.
		if err := syncPairingDirectory(filepath.Dir(s.path)); err != nil {
			return fmt.Errorf("%w: %v", ErrTrustStoreDurability, err)
		}
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
	if err := s.saveLocked(); err != nil {
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

func (s *Store) saveLocked() error {
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
	if err := replaceStoreFile(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	// The shared Store retains its preexisting contract. Pairing takes an
	// additional durability step under the same lock in PutPairing.
	return os.Chmod(s.path, 0o600)
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

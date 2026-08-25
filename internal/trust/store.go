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

type Store struct {
	mu    sync.Mutex
	path  string
	Peers map[string]Peer `json:"peers"`
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, Peers: map[string]Peer{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure trust store permissions: %w", err)
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parse trust store: %w", err)
	}
	if s.Peers == nil {
		s.Peers = map[string]Peer{}
	}
	return s, nil
}

func (s *Store) Get(id string) (Peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.Peers[id]
	return p, ok
}

func (s *Store) FindByFingerprint(fp string) (Peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.Peers {
		if p.Fingerprint == fp {
			return p, true
		}
	}
	return Peer{}, false
}

func (s *Store) Put(p Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.TrustedAt.IsZero() {
		p.TrustedAt = time.Now().UTC()
	}
	s.Peers[p.ID] = p
	return s.saveLocked()
}

func (s *Store) List() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Peer, 0, len(s.Peers))
	for _, p := range s.Peers {
		out = append(out, p)
	}
	return out
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
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

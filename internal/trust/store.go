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

type Store struct {
	mu    sync.Mutex
	path  string
	Peers map[string]Peer `json:"peers"`
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, Peers: map[string]Peer{}}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("trust store must not be a symbolic link")
	}
	if info.Size() <= 0 || info.Size() > maxStoreSize {
		return nil, errors.New("trust store has an invalid size")
	}
	data, err := os.ReadFile(path)
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
	return os.Chmod(s.path, 0o600)
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

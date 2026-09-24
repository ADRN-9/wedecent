package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	FileName          = "audit.jsonl"
	archiveFileName   = "audit.jsonl.1"
	defaultMaxLogSize = 16 << 20
	maxEventSize      = 4 << 10
	maxFieldLength    = 512
)

var eventNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,95}$`)

// Event is deliberately narrow: audit records may identify actors, peers,
// transports, and stable reason codes, but they have no arbitrary payload field.
// Terminal data, pairing secrets, grants, credentials, and private keys must
// never be written to the audit log.
type Event struct {
	Time      time.Time `json:"time"`
	Type      string    `json:"type"`
	Outcome   string    `json:"outcome"`
	ActorID   string    `json:"actor_id,omitempty"`
	PeerID    string    `json:"peer_id,omitempty"`
	Transport string    `json:"transport,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

type Log struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	now      func() time.Time
}

func Open(stateDir string) (*Log, error) {
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return nil, errors.New("audit state directory is required")
	}
	return open(filepath.Join(stateDir, FileName), defaultMaxLogSize)
}

func open(path string, maxBytes int64) (*Log, error) {
	if maxBytes < maxEventSize {
		return nil, errors.New("audit log size limit is too small")
	}
	log := &Log{path: path, maxBytes: maxBytes, now: time.Now}
	if err := log.validateExisting(); err != nil {
		return nil, err
	}
	return log, nil
}

func (l *Log) Path() string { return l.path }

func (l *Log) Append(event Event) error {
	if l == nil {
		return errors.New("audit log is nil")
	}
	if err := validateEvent(&event); err != nil {
		return err
	}
	if event.Time.IsZero() {
		event.Time = l.now().UTC()
	} else {
		event.Time = event.Time.UTC()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxEventSize {
		return errors.New("audit event exceeds size limit")
	}

	unlock, err := lockFile(l.path)
	if err != nil {
		return err
	}
	defer unlock()

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureCapacity(int64(len(data))); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("secure audit log permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync audit event: %w", err)
	}
	return nil
}

func validateEvent(event *Event) error {
	event.Type = strings.TrimSpace(event.Type)
	event.Outcome = strings.TrimSpace(event.Outcome)
	event.ActorID = strings.TrimSpace(event.ActorID)
	event.PeerID = strings.TrimSpace(event.PeerID)
	event.Transport = strings.TrimSpace(event.Transport)
	event.Reason = strings.TrimSpace(event.Reason)
	if !eventNamePattern.MatchString(event.Type) {
		return errors.New("audit event type is invalid")
	}
	if !eventNamePattern.MatchString(event.Outcome) {
		return errors.New("audit event outcome is invalid")
	}
	for name, value := range map[string]string{
		"actor_id": event.ActorID, "peer_id": event.PeerID,
		"transport": event.Transport, "reason": event.Reason,
	} {
		if len(value) > maxFieldLength {
			return fmt.Errorf("audit field %s exceeds size limit", name)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("audit field %s contains invalid control characters", name)
		}
	}
	return nil
}

func (l *Log) validateExisting() error {
	info, err := os.Lstat(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("audit log must be a regular file, not a symbolic link")
	}
	if info.Size() > l.maxBytes {
		return errors.New("audit log exceeds size limit")
	}
	return os.Chmod(l.path, 0o600)
}

func (l *Log) ensureCapacity(additional int64) error {
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	info, err := os.Lstat(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("audit log must be a regular file, not a symbolic link")
	}
	if info.Size()+additional <= l.maxBytes {
		return nil
	}

	archive := filepath.Join(dir, archiveFileName)
	if archiveInfo, err := os.Lstat(archive); err == nil {
		if archiveInfo.Mode()&os.ModeSymlink != 0 || !archiveInfo.Mode().IsRegular() {
			return errors.New("audit archive must be a regular file, not a symbolic link")
		}
		if err := os.Remove(archive); err != nil {
			return fmt.Errorf("remove previous audit archive: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat audit archive: %w", err)
	}
	if err := os.Rename(l.path, archive); err != nil {
		return fmt.Errorf("rotate audit log: %w", err)
	}
	if err := os.Chmod(archive, 0o600); err != nil {
		return fmt.Errorf("secure audit archive permissions: %w", err)
	}
	return nil
}

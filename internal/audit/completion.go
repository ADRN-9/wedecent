package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"wedecent.com/wedecent/internal/trust"
)

// VerifyDurableEvent examines the current and single rotated audit files
// under the same cross-process lock used by Append. The retained recovery
// proof—not these rotating files—is the authoritative long-term copy.
func (l *Log) VerifyDurableEvent(event Event) error {
	if l == nil || event.Time.IsZero() || event.AttemptID == "" {
		return errors.New("pairing audit verification requires an exact timestamp and attempt")
	}
	copyEvent := event
	if err := validateEvent(&copyEvent); err != nil || copyEvent != event {
		return errors.New("invalid pairing audit verification event")
	}
	target, err := json.Marshal(event)
	if err != nil {
		return err
	}
	unlock, err := lockFile(l.path)
	if err != nil {
		return err
	}
	defer unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, path := range []string{l.path, filepath.Join(filepath.Dir(l.path), archiveFileName)} {
		match, err := l.findAndSyncAuditEvent(path, target)
		if err != nil {
			return err
		}
		if match {
			return l.syncDirectory(filepath.Dir(l.path))
		}
	}
	return errors.New("pairing completion is no longer independently present in synchronized audit logs")
}

func (l *Log) findAndSyncAuditEvent(path string, target []byte) (bool, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !before.Mode().IsRegular() || before.Size() > l.maxBytes {
		return false, errors.New("audit proof source is unsafe or oversized")
	}
	if err := trust.VerifyPairingStatePath(path); err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return false, errors.New("audit proof source was replaced during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, l.maxBytes+1))
	if err != nil {
		return false, err
	}
	if int64(len(data)) > l.maxBytes ||
		(len(data) != 0 && data[len(data)-1] != '\n') {
		return false, errors.New("audit proof source contains truncated or oversized records")
	}
	found := false
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if len(line) > maxEventSize {
			return false, errors.New("audit proof source contains oversized event")
		}
		var parsed Event
		if err := json.Unmarshal(line, &parsed); err != nil {
			return false, fmt.Errorf("malformed audit proof source: %w", err)
		}
		if bytes.Equal(line, target) {
			found = true
		}
	}
	if err := f.Sync(); err != nil {
		return false, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) {
		return false, errors.New("audit proof source replaced during sync")
	}
	return found, nil
}

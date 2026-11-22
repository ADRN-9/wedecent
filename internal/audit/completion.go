package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
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
	matches := 0
	for _, path := range []string{l.path, filepath.Join(filepath.Dir(l.path), archiveFileName)} {
		count, err := l.findAndSyncAuditEvent(path, target)
		if err != nil {
			return err
		}
		matches += count
	}
	switch matches {
	case 0:
		return errors.New("pairing completion is no longer independently present in synchronized audit logs")
	case 1:
		return l.syncDirectory(filepath.Dir(l.path))
	default:
		return errors.New("pairing completion audit event is duplicated across synchronized audit logs")
	}
}

func (l *Log) findAndSyncAuditEvent(path string, target []byte) (int, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !before.Mode().IsRegular() || before.Size() > l.maxBytes {
		return 0, errors.New("audit proof source is unsafe or oversized")
	}
	if err := trust.VerifyPairingStatePath(path); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return 0, errors.New("audit proof source was replaced during open")
	}

	// The reader retains at most one bounded JSONL record. The extra byte
	// distinguishes a file exactly at the limit from one byte over it.
	limited := &io.LimitedReader{R: f, N: l.maxBytes + 1}
	reader := bufio.NewReaderSize(limited, maxEventSize)
	var bytesRead int64
	matches := 0
	for {
		line, readErr := reader.ReadSlice('\n')
		bytesRead += int64(len(line))
		if bytesRead > l.maxBytes {
			return 0, errors.New("audit proof source exceeds file size limit")
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			return 0, errors.New("audit proof source contains oversized event")
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return 0, errors.New("audit proof source could not be read")
		}
		if errors.Is(readErr, io.EOF) {
			if len(line) == 0 {
				break
			}
			return 0, errors.New("audit proof source contains unterminated record")
		}
		if len(line) == 0 || line[len(line)-1] != '\n' {
			return 0, errors.New("audit proof source contains unterminated record")
		}
		// Append enforces maxEventSize on the serialized JSON plus newline.
		if len(line) > maxEventSize {
			return 0, errors.New("audit proof source contains oversized event")
		}
		record := line[:len(line)-1]
		if len(record) == 0 {
			return 0, errors.New("audit proof source contains blank record")
		}
		if _, err := decodeAuditProofEvent(record); err != nil {
			// Do not return decoder details: audit records can contain sensitive
			// identifiers even though the schema intentionally excludes secrets.
			return 0, errors.New("audit proof source contains invalid event")
		}
		if bytes.Equal(record, target) {
			matches++
		}
	}

	if err := f.Sync(); err != nil {
		return 0, err
	}
	current, err := f.Stat()
	if err != nil || !os.SameFile(opened, current) ||
		current.Size() != bytesRead || !current.ModTime().Equal(opened.ModTime()) {
		return 0, errors.New("audit proof source changed during synchronization")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) ||
		after.Size() != bytesRead || !after.ModTime().Equal(opened.ModTime()) {
		return 0, errors.New("audit proof source replaced during sync")
	}
	return matches, nil
}

// auditProofEventFields defines the strict v1 JSON schema. Exact JSON tag
// spellings are required; unknown fields and case-folded aliases are rejected.
// Compatibility policy: additive Event fields require a coordinated reader
// update. Older verifiers intentionally fail closed on newer schema fields.
var auditProofEventFields = map[string]struct{}{
	"time": {}, "type": {}, "outcome": {}, "actor_id": {}, "peer_id": {},
	"session_id": {}, "attempt_id": {}, "authorization_run_id": {},
	"validation_attempt_id": {}, "consumption_attempt_id": {},
	"validation_event_id": {}, "consumption_event_id": {}, "transport": {},
	"transport_provenance": {}, "underlying_transport": {}, "route_router_id": {},
	"stream_id": {}, "reason": {},
}

func decodeAuditProofEvent(record []byte) (Event, error) {
	var event Event
	schema := json.NewDecoder(bytes.NewReader(record))
	schema.UseNumber()
	root, err := schema.Token()
	if err != nil {
		return event, err
	}
	rootDelimiter, ok := root.(json.Delim)
	if !ok || rootDelimiter != '{' {
		return event, errors.New("audit event must be a JSON object")
	}

	seen := make(map[string]struct{}, len(auditProofEventFields))
	for schema.More() {
		keyToken, err := schema.Token()
		if err != nil {
			return event, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return event, errors.New("audit event object key is invalid")
		}
		if _, ok := auditProofEventFields[key]; !ok {
			return event, errors.New("audit event contains an unknown field")
		}
		if _, exists := seen[key]; exists {
			return event, errors.New("audit event contains a duplicate JSON key")
		}
		seen[key] = struct{}{}
		value, err := schema.Token()
		if err != nil {
			return event, err
		}
		if err := consumeAuditJSONValue(schema, value); err != nil {
			return event, err
		}
	}
	closing, err := schema.Token()
	if err != nil || closing != json.Delim('}') {
		return event, errors.New("audit event object is incomplete")
	}
	for _, required := range []string{"time", "type", "outcome"} {
		if _, ok := seen[required]; !ok {
			return event, errors.New("audit event is missing a required field")
		}
	}
	if _, err := schema.Token(); !errors.Is(err, io.EOF) {
		return event, errors.New("audit event contains trailing JSON data")
	}

	decoder := json.NewDecoder(bytes.NewReader(record))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return Event{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Event{}, errors.New("audit event contains trailing JSON data")
	}
	if event.Time.IsZero() {
		return Event{}, errors.New("audit event timestamp is zero")
	}
	validated := event
	if err := validateEvent(&validated); err != nil || validated != event {
		return Event{}, errors.New("audit event fields are invalid")
	}
	return event, nil
}

// consumeAuditJSONValue recursively checks nested objects too, so duplicate
// keys cannot be hidden inside a value. Record-size bounds cap its memory use.
func consumeAuditJSONValue(decoder *json.Decoder, token json.Token) error {
	if token == nil {
		return errors.New("JSON null values are not permitted in audit events")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("audit event object key is invalid")
			}
			if _, exists := seen[key]; exists {
				return errors.New("audit event contains a duplicate JSON key")
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeAuditJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("audit event object is incomplete")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeAuditJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("audit event array is incomplete")
		}
	default:
		return errors.New("audit event contains an invalid JSON delimiter")
	}
	return nil
}

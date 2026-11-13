package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppendWritesStructuredJSONL(t *testing.T) {
	dir := t.TempDir()
	log, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 9, 23, 12, 34, 56, 0, time.UTC)
	log.now = func() time.Time { return fixed }
	if err := log.Append(Event{Type: "terminal.stream_opened", Outcome: "success", ActorID: "wd_client", PeerID: "wd_agent", Transport: "direct", StreamID: 7}); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatalf("missing audit line: %v", scanner.Err())
	}
	var event Event
	if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Time != fixed || event.Type != "terminal.stream_opened" || event.Outcome != "success" || event.ActorID != "wd_client" || event.PeerID != "wd_agent" || event.Transport != "direct" || event.StreamID != 7 {
		t.Fatalf("unexpected event: %+v", event)
	}
	if scanner.Scan() {
		t.Fatal("expected exactly one audit line")
	}
}

func TestAppendRejectsControlCharacters(t *testing.T) {
	log, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(Event{Type: "pairing.trust_added", Outcome: "success", PeerID: "peer\nsecret"}); err == nil {
		t.Fatal("expected control-character rejection")
	}
}

func TestAppendRotatesBoundedLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	log, err := open(path, maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	log.now = func() time.Time { return time.Unix(1, 0).UTC() }
	for i := 0; i < 80; i++ {
		if err := log.Append(Event{Type: "terminal.session_closed", Outcome: "success", Reason: strings.Repeat("x", 80)}); err != nil {
			t.Fatal(err)
		}
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Size() > log.maxBytes {
		t.Fatalf("active log exceeded bound: %d > %d", info.Size(), log.maxBytes)
	}
	archive := filepath.Join(dir, archiveFileName)
	if info, err := os.Stat(archive); err != nil {
		t.Fatal(err)
	} else if info.Size() > log.maxBytes {
		t.Fatalf("archive exceeded bound: %d > %d", info.Size(), log.maxBytes)
	}
}

func TestOpenRejectsSymlinkLog(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, FileName)
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := Open(dir)
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestOpenRejectsOversizeExistingLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, make([]byte, maxEventSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := open(path, maxEventSize)
	if err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("expected oversize rejection, got %v", err)
	}
}

func TestAppendRejectsInvalidEventName(t *testing.T) {
	log, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = log.Append(Event{Type: "Terminal Opened", Outcome: "success"})
	if err == nil || !strings.Contains(err.Error(), "event type") {
		t.Fatalf("expected invalid event type, got %v", err)
	}
}

func TestAppendAuditDirectorySyncFailureIsNotAcknowledged(t *testing.T) {
	dir := t.TempDir()
	log, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	log.syncDir = func(string) error { return errors.New("injected metadata sync failure") }
	err = log.Append(Event{Type: "pairing.request", Outcome: "pending", PeerID: "wd_aaaaaaaaaaaaaaaa"})
	if err == nil || !strings.Contains(err.Error(), "sync audit directory") {
		t.Fatalf("append with failed metadata sync reported success: %v", err)
	}
	// The line can already be visible, even though durability is uncertain.
	// The pairing protocol must not consume a secret on this return path.
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil || !strings.Contains(string(data), `"outcome":"pending"`) {
		t.Fatalf("unacknowledged pending event is not readable: %q, %v", data, err)
	}
	log, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(Event{Type: "pairing.request", Outcome: "denied", PeerID: "wd_aaaaaaaaaaaaaaaa"}); err != nil {
		t.Fatalf("audit recovery after restart: %v", err)
	}
}

func TestAuditRotationPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	log, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	log.syncDir = syncAuditDirectory
	rotated := false
	for i := 0; i < 100; i++ {
		err := log.Append(Event{Type: "terminal.session_closed", Outcome: "success", Reason: strings.Repeat("x", 250)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, archiveFileName)); err == nil {
			rotated = true
			break
		}
	}
	if !rotated {
		t.Fatal("test never rotated the audit log")
	}
	// A successful archive replacement and subsequent startup must preserve
	// readable events in both the archive and current log.
	restarted, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Append(Event{Type: "pairing.request", Outcome: "pending", PeerID: "wd_aaaaaaaaaaaaaaaa"}); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil || len(archive) == 0 {
		t.Fatalf("rotated log not readable after restart: %v", err)
	}
}

func TestAuditRotationMetadataFailureIsNotAcknowledged(t *testing.T) {
	dir := t.TempDir()
	log, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(dir, archiveFileName)
	log.syncDir = func(d string) error {
		if _, err := os.Stat(archivePath); err == nil {
			return errors.New("injected post-rename directory sync failure")
		}
		return syncAuditDirectory(d)
	}
	sawFailure := false
	for i := 0; i < 100; i++ {
		err := log.Append(Event{Type: "terminal.session_closed", Outcome: "success", Reason: strings.Repeat("x", 250)})
		if err != nil {
			if !strings.Contains(err.Error(), "sync rotated audit directory") {
				t.Fatalf("unexpected append error: %v", err)
			}
			sawFailure = true
			break
		}
	}
	if !sawFailure {
		t.Fatal("audit rotation sync failure was not exercised")
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil || len(archive) == 0 {
		t.Fatalf("audit archive disappeared after metadata failure: %v", err)
	}
	restarted, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Append(Event{Type: "pairing.request", Outcome: "pending", PeerID: "wd_aaaaaaaaaaaaaaaa"}); err != nil {
		t.Fatalf("audit restart after uncertain rotation: %v", err)
	}
}

func TestPendingPairingAuditDetectableAfterOneRotationAndRestart(t *testing.T) {
	dir := t.TempDir()
	log, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	peer := "wd_aaaaaaaaaaaaaaaa"
	if err := log.Append(Event{Type: "pairing.request", Outcome: "pending", PeerID: peer}); err != nil {
		t.Fatal(err)
	}
	rotated := false
	for i := 0; i < 80; i++ {
		if err := log.Append(Event{Type: "terminal.session_closed", Outcome: "success", Reason: strings.Repeat("x", 260)}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, archiveFileName)); err == nil {
			rotated = true
			break
		}
	}
	if !rotated {
		t.Fatal("audit log did not rotate")
	}
	archive, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(archive), `"type":"pairing.request","outcome":"pending"`) ||
		!strings.Contains(string(archive), peer) {
		t.Fatal("unresolved pending pairing record missing from rotated archive")
	}
	restarted, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Append(Event{Type: "pairing.recovery", Outcome: "pending", PeerID: peer}); err != nil {
		t.Fatal(err)
	}
	// This test proves one rotation, not indefinite retention: a second
	// rotation can evict the record. Production recovery retention is a gate.
}

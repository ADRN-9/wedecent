package audit

import (
	"bufio"
	"encoding/json"
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

func TestAppendRejectsInvalidUTF8InEveryStringField(t *testing.T) {
	invalidUTF8 := string([]byte{0xff})
	tests := []struct {
		name  string
		mutate func(*Event)
	}{
		{"type", func(event *Event) { event.Type += invalidUTF8 }},
		{"outcome", func(event *Event) { event.Outcome += invalidUTF8 }},
		{"actor_id", func(event *Event) { event.ActorID = "actor-" + invalidUTF8 }},
		{"peer_id", func(event *Event) { event.PeerID = "peer-" + invalidUTF8 }},
		{"transport", func(event *Event) { event.Transport = "transport-" + invalidUTF8 }},
		{"reason", func(event *Event) { event.Reason = "reason-" + invalidUTF8 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			log, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			event := Event{Type: "terminal.stream_opened", Outcome: "success"}
			test.mutate(&event)

			err = log.Append(event)
			if err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
				t.Fatalf("expected invalid UTF-8 rejection, got %v", err)
			}
			if _, err := os.Lstat(log.Path()); !os.IsNotExist(err) {
				t.Fatalf("rejected event created a durable audit record: %v", err)
			}
			archive := filepath.Join(filepath.Dir(log.Path()), archiveFileName)
			if _, err := os.Lstat(archive); !os.IsNotExist(err) {
				t.Fatalf("rejected event created an audit archive: %v", err)
			}
		})
	}
}

func TestAppendAcceptsValidUnicodeAndReplacementCharacter(t *testing.T) {
	log, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 11, 22, 12, 34, 56, 0, time.UTC)
	log.now = func() time.Time { return fixed }
	event := Event{
		Type:      "terminal.stream_opened",
		Outcome:   "success",
		ActorID:   "cliënt-東京",
		PeerID:    "peer-🙂",
		Transport: "direct-🌐",
		Reason:    "café 東京 🙂 \uFFFD",
	}
	if err := log.Append(event); err != nil {
		t.Fatalf("valid Unicode event was rejected: %v", err)
	}

	data, err := os.ReadFile(log.Path())
	if err != nil {
		t.Fatal(err)
	}
	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Time.Equal(fixed) ||
		got.Type != event.Type ||
		got.Outcome != event.Outcome ||
		got.ActorID != event.ActorID ||
		got.PeerID != event.PeerID ||
		got.Transport != event.Transport ||
		got.Reason != event.Reason {
		t.Fatalf("Unicode audit event changed during serialization: got %+v, want %+v", got, event)
	}
	if !strings.Contains(string(data), "\uFFFD") {
		t.Fatal("legitimate U+FFFD was not preserved in the audit record")
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

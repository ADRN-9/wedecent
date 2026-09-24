package session

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
)

func TestRecordAuditPersistsActorAndStableFields(t *testing.T) {
	stateDir := t.TempDir()
	server := &Server{
		Identity: &identity.Identity{ID: "wd_abcdefghijklmnop"},
		StateDir: stateDir,
	}
	server.recordAudit(audit.Event{
		Type:      "terminal.authorization",
		Outcome:   "denied",
		PeerID:    "wd_ponmlkjihgfedcba",
		Transport: "direct",
		Reason:    "authorization_rejected",
	})

	f, err := os.Open(filepath.Join(stateDir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatalf("missing audit event: %v", scanner.Err())
	}
	var event audit.Event
	if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.ActorID != server.Identity.ID || event.PeerID != "wd_ponmlkjihgfedcba" || event.Type != "terminal.authorization" || event.Outcome != "denied" || event.Transport != "direct" || event.Reason != "authorization_rejected" {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestRecordAuditDoesNothingWithoutStateDir(t *testing.T) {
	server := &Server{Identity: &identity.Identity{ID: "wd_abcdefghijklmnop"}}
	server.recordAudit(audit.Event{Type: "terminal.session_opened", Outcome: "success"})
}

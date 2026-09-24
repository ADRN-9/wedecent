package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/trust"
)

func TestRunClientsRevokeAuditsAttemptAndSuccess(t *testing.T) {
	stateDir := t.TempDir()
	store, err := trust.Open(filepath.Join(stateDir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	peer := trust.Peer{ID: "wd_abcdefghijklmnop", Name: "client", Fingerprint: "SHA256:test"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}

	if err := runClientsRevoke([]string{"--state", stateDir, peer.ID}); err != nil {
		t.Fatal(err)
	}

	events := readAgentAuditEvents(t, filepath.Join(stateDir, audit.FileName))
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d: %+v", len(events), events)
	}
	if events[0].Type != "trust.client_revoke" || events[0].Outcome != "attempt" || events[0].PeerID != peer.ID {
		t.Fatalf("unexpected attempt event: %+v", events[0])
	}
	if events[1].Type != "trust.client_revoke" || events[1].Outcome != "success" || events[1].PeerID != peer.ID {
		t.Fatalf("unexpected success event: %+v", events[1])
	}
}

func readAgentAuditEvents(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []audit.Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var event audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

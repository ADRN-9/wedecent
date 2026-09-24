package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/audit"
)

func TestRouterControllerTrustAndRevokeAreAudited(t *testing.T) {
	stateDir := t.TempDir()
	controller := controllerTestIdentity(t, "controller")
	fingerprint := controllerTestFingerprint(t, controller)

	if err := runTrust(stateDir, []string{"--id", controller.ID, "--fingerprint", fingerprint}); err != nil {
		t.Fatal(err)
	}
	if err := runRevoke(stateDir, []string{"--id", controller.ID}); err != nil {
		t.Fatal(err)
	}

	events := readRouterCtlAuditEvents(t, filepath.Join(stateDir, audit.FileName))
	if len(events) != 4 {
		t.Fatalf("expected four audit events, got %d: %+v", len(events), events)
	}
	wantTypes := []string{"router.controller_trust", "router.controller_trust", "router.controller_revoke", "router.controller_revoke"}
	wantOutcomes := []string{"attempt", "success", "attempt", "success"}
	for i := range events {
		if events[i].Type != wantTypes[i] || events[i].Outcome != wantOutcomes[i] || events[i].PeerID != controller.ID {
			t.Fatalf("event %d = %+v", i, events[i])
		}
	}
}

func readRouterCtlAuditEvents(t *testing.T, path string) []audit.Event {
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

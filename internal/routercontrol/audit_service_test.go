package routercontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type auditRouterServiceStub struct {
	setErr error
}

func (s *auditRouterServiceStub) GetRouterPolicy(context.Context) (v1.RouterPolicy, error) {
	return v1.RouterPolicy{}, nil
}

func (s *auditRouterServiceStub) SetRouterPolicy(_ context.Context, req v1.SetRouterPolicyRequest) (v1.RouterPolicy, error) {
	if s.setErr != nil {
		return v1.RouterPolicy{}, s.setErr
	}
	return req.Policy, nil
}

func (s *auditRouterServiceStub) GetRouterStats(context.Context) (v1.RouterStats, error) {
	return v1.RouterStats{}, nil
}

func TestAuditedRouterServiceRecordsPolicyMutation(t *testing.T) {
	stateDir := t.TempDir()
	log, err := audit.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	service := newAuditedRouterService(&auditRouterServiceStub{}, log, "wd_agentagentagent")
	ctx := withRouterAuditActor(context.Background(), "wd_controllerctrl")
	want := v1.RouterPolicy{Enabled: true, TrustedDevicesOnly: true, MaxSessions: 4}
	got, err := service.SetRouterPolicy(ctx, v1.SetRouterPolicyRequest{Policy: want})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("unexpected policy: %+v", got)
	}
	events := readRouterAuditEvents(t, filepath.Join(stateDir, audit.FileName))
	if len(events) != 2 {
		t.Fatalf("expected attempt and success, got %+v", events)
	}
	if events[0].Type != "router.policy_set" || events[0].Outcome != "attempt" || events[0].ActorID != "wd_controllerctrl" || events[0].PeerID != "wd_agentagentagent" {
		t.Fatalf("unexpected attempt event: %+v", events[0])
	}
	if events[1].Outcome != "success" {
		t.Fatalf("unexpected success event: %+v", events[1])
	}
}

func TestAuditedRouterServiceRecordsStableFailureReason(t *testing.T) {
	stateDir := t.TempDir()
	log, err := audit.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	service := newAuditedRouterService(&auditRouterServiceStub{setErr: coreapi.ErrInvalidRouterPolicy}, log, "wd_agentagentagent")
	_, err = service.SetRouterPolicy(context.Background(), v1.SetRouterPolicyRequest{})
	if err == nil {
		t.Fatal("expected policy error")
	}
	events := readRouterAuditEvents(t, filepath.Join(stateDir, audit.FileName))
	if len(events) != 2 || events[1].Outcome != "failed" || events[1].Reason != "invalid_policy" {
		t.Fatalf("unexpected failure events: %+v", events)
	}
}

func readRouterAuditEvents(t *testing.T, path string) []audit.Event {
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

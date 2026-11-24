package portforward

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
)

func TestCheckpointAuditTrustRequiresIndependentHostnameAndSPKIPins(t *testing.T) {
	pinA := strings.Repeat("a", sha256.Size*2)
	pinB := strings.Repeat("b", sha256.Size*2)
	trust := CheckpointAuditTrust{Hostname: "audit.example.com", Port: 443, SPKISHA256Pins: pinA + "," + pinB}
	pins, err := parseCheckpointAuditPins(trust.SPKISHA256Pins)
	if err != nil || len(pins) != 2 {
		t.Fatalf("valid overlapping pin set rejected: pins=%d err=%v", len(pins), err)
	}
	if _, err := parseCheckpointAuditPins(pinA + "," + pinA); err == nil {
		t.Fatal("duplicate rotation pin accepted")
	}
	if _, err := parseCheckpointAuditPins(strings.ToUpper(pinA)); err == nil {
		t.Fatal("non-canonical uppercase pin accepted")
	}
	if _, err := parseCheckpointAuditPins(pinA[:sha256.Size*2-1]); err == nil {
		t.Fatal("truncated pin accepted")
	}
	if validCheckpointAuditAuthority("Audit.Example.com", 443) || validCheckpointAuditAuthority("audit.example.com.", 443) ||
		validCheckpointAuditAuthority("audit.example.com", 0) {
		t.Fatal("non-canonical independent audit authority accepted")
	}
}

func TestCheckpointAuditEndpointCannotFollowMutableSessionOrigin(t *testing.T) {
	trust := CheckpointAuditTrust{
		Hostname: "audit.example.com", Port: 443,
		SPKISHA256Pins: strings.Repeat("a", sha256.Size*2),
	}
	session := &account.Session{SupabaseURL: "https://audit.example.com"}
	endpoint, err := auditEndpoint(session, trust)
	if err != nil || endpoint != "https://audit.example.com/functions/v1/port-forward-finalization-audit" {
		t.Fatalf("trusted endpoint mismatch: endpoint=%q err=%v", endpoint, err)
	}
	for _, raw := range []string{
		"https://attacker.example.com",
		"https://audit.example.com:8443",
		"http://audit.example.com",
		"https://audit.example.com/path",
		"https://user@audit.example.com",
		"https://audit.example.com?redirect=attacker",
	} {
		session.SupabaseURL = raw
		if _, err := auditEndpoint(session, trust); err == nil {
			t.Fatalf("untrusted session origin accepted: %s", raw)
		}
	}
}

func TestCheckpointAuditEvidenceSerializationRejectsUnsafeUint64(t *testing.T) {
	evidence := &CheckpointFinalizationEvidence{
		PrimaryReceipt: CheckpointReceipt{
			Version: 1, Generation: 1,
			DeviceID: "wd_aaaaaaaaaaaaaaaa",
			Signature: make([]byte, 64),
		},
	}
	if payload, err := checkpointFinalizationEvidencePayload(evidence); err != nil || payload["primary_receipt"] == nil {
		t.Fatalf("valid evidence serialization failed: payload=%v err=%v", payload, err)
	}
	evidence.PrimaryReceipt.Generation = 1<<53
	if _, err := checkpointFinalizationEvidencePayload(evidence); err == nil {
		t.Fatal("uint64 beyond JavaScript safe integer range was serialized")
	}
}

func TestCheckpointAuditConstructorRequiresTrustAndMatchingSession(t *testing.T) {
	path := t.TempDir() + "/account-session.json"
	session := &account.Session{
		Version: account.SessionVersion, SupabaseURL: "https://audit.example.com",
		PublishableKey: "sb_publishable_test", UserID: "11000000-0000-4000-8000-000000000091",
		Email: "audit@example.test", AccessToken: "access", RefreshToken: "refresh",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	if err := account.Save(path, session); err != nil {
		t.Fatal(err)
	}
	trust := CheckpointAuditTrust{Hostname: "audit.example.com", Port: 443, SPKISHA256Pins: strings.Repeat("a", 64)}
	if _, err := NewSupabaseCheckpointFinalizationAuditor(account.Client{}, path, CheckpointAuditTrust{}); err == nil {
		t.Fatal("missing independent audit trust accepted")
	}
	if _, err := NewSupabaseCheckpointFinalizationAuditor(account.Client{}, path, trust); err != nil {
		t.Fatalf("valid independent audit trust rejected: %v", err)
	}
	trust.Hostname = "attacker.example.com"
	if _, err := NewSupabaseCheckpointFinalizationAuditor(account.Client{}, path, trust); err == nil {
		t.Fatal("session-controlled Supabase origin overrode independent hostname")
	}
}

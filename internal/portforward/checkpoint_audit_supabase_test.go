package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
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


func TestCheckpointAuditTLSRequiresTLS13HostnameAndMatchingSPKI(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "audit.example.com"},
		DNSNames: []string{"audit.example.com"},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	config := checkpointAuditTLSConfig(CheckpointAuditTrust{Hostname: "audit.example.com", Port: 443}, [][sha256.Size]byte{pin})
	if config.MinVersion != tls.VersionTLS13 || config.ServerName != "audit.example.com" {
		t.Fatalf("TLS trust config weakened: min=%d server=%q", config.MinVersion, config.ServerName)
	}
	if err := config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}); err != nil {
		t.Fatalf("matching SPKI rejected: %v", err)
	}
	wrong := pin
	wrong[0] ^= 0xff
	wrongConfig := checkpointAuditTLSConfig(CheckpointAuditTrust{Hostname: "audit.example.com", Port: 443}, [][sha256.Size]byte{wrong})
	if err := wrongConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}); err == nil {
		t.Fatal("wrong SPKI pin accepted")
	}
	if err := config.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("missing peer certificate accepted")
	}
}

func TestCheckpointAuditRedirectsAndCanceledRequestsFailClosed(t *testing.T) {
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
	auditor, err := NewSupabaseCheckpointFinalizationAuditor(account.Client{}, path, trust)
	if err != nil {
		t.Fatal(err)
	}
	if err := auditor.http.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v, want ErrUseLastResponse", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := auditor.RecordCheckpointFinalization(ctx, CheckpointRequest{}, "", CheckpointFinalizationStarted, nil); err != context.Canceled {
		t.Fatalf("canceled audit request returned %v", err)
	}
}


func TestCheckpointAuditConstructorRequiresAuthenticatedSession(t *testing.T) {
	trust := CheckpointAuditTrust{Hostname: "audit.example.com", Port: 443, SPKISHA256Pins: strings.Repeat("a", 64)}
	if _, err := NewSupabaseCheckpointFinalizationAuditor(account.Client{}, t.TempDir()+"/missing-session.json", trust); err == nil {
		t.Fatal("missing authenticated account session accepted")
	}
}

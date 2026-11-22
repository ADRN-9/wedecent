package agentadmission

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
)

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &identity.Identity{ID: identity.DeviceID(pub), PublicKey: pub, PrivateKey: priv}
}

func TestAcquireUsesDeviceProofWithoutUserBearer(t *testing.T) {
	id := testIdentity(t)
	now := time.Unix(1_800_000_000, 0)
	fingerprint, err := identity.FingerprintPublicKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var request admissionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("agent admission request must not contain a user bearer token")
		}
		if r.Header.Get("apikey") != "public-test-key" {
			t.Fatalf("apikey = %q", r.Header.Get("apikey"))
		}
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control = %q", r.Header.Get("Cache-Control"))
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.DeviceID != id.ID || request.Slot != 7 {
			t.Fatalf("request scope = %q/%d", request.DeviceID, request.Slot)
		}
		parts := strings.Split(request.Proof, ".")
		if len(parts) != 3 {
			t.Fatal("device proof is not a JWT")
		}
		var header proofHeader
		if err := decodePart(parts[0], &header); err != nil {
			t.Fatal(err)
		}
		var claims proofClaims
		if err := decodePart(parts[1], &claims); err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || !ed25519.Verify(id.PublicKey, []byte(parts[0]+"."+parts[1]), signature) {
			t.Fatal("device proof signature did not verify")
		}
		if header.KeyID != fingerprint || claims.DeviceID != id.ID ||
			claims.PublicKeyFingerprint != fingerprint || claims.Slot != 7 ||
			claims.Audience != proofAudience || claims.Purpose != proofPurpose ||
			claims.ExpiresAt-claims.IssuedAt != int64(proofLifetime/time.Second) {
			t.Fatalf("unexpected proof claims: %+v", claims)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"agent_admission":"` + issueCapability(t, id.ID, fingerprint, 7, now) + `"}`))
	}))
	defer server.Close()

	client := Client{
		SupabaseURL: server.URL, PublishableKey: "public-test-key",
		HTTP: server.Client(), Now: func() time.Time { return now },
	}
	token, err := client.Acquire(context.Background(), id, 7)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || request.Proof == "" {
		t.Fatal("expected a device proof and an admission capability")
	}
}

func TestAcquireGeneratesFreshProofNonceForEachReconnect(t *testing.T) {
	id := testIdentity(t)
	now := time.Unix(1_800_000_000, 0)
	fingerprint, _ := identity.FingerprintPublicKey(id.PublicKey)
	seen := make(map[string]bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request admissionRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(request.Proof, ".")
		if len(parts) != 3 {
			t.Fatal("device proof is not a JWT")
		}
		var claims proofClaims
		if err := decodePart(parts[1], &claims); err != nil {
			t.Fatal(err)
		}
		if seen[claims.TokenID] {
			t.Fatal("device proof nonce was reused across reconnects")
		}
		seen[claims.TokenID] = true
		_, _ = w.Write([]byte(`{"agent_admission":"` + issueCapability(t, id.ID, fingerprint, 5, now) + `"}`))
	}))
	defer server.Close()
	client := Client{
		SupabaseURL: server.URL,
		PublishableKey: "public-test-key",
		HTTP: server.Client(),
		Now: func() time.Time { return now },
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := client.Acquire(context.Background(), id, 5); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("received %d proof nonces, want 2", len(seen))
	}
}

func TestAcquireRejectsCapabilitySubstitution(t *testing.T) {
	id := testIdentity(t)
	now := time.Unix(1_800_000_000, 0)
	fingerprint, _ := identity.FingerprintPublicKey(id.PublicKey)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		token := issueCapability(t, "wd_4ksk5edkttwsxqx4", fingerprint, 3, now)
		_, _ = w.Write([]byte(`{"agent_admission":"` + token + `"}`))
	}))
	defer server.Close()
	client := Client{SupabaseURL: server.URL, PublishableKey: "public-test-key", HTTP: server.Client(), Now: func() time.Time { return now }}
	if _, err := client.Acquire(context.Background(), id, 3); err == nil {
		t.Fatal("expected substituted device capability to fail")
	}
}

func TestAcquireRejectsExpiredCapability(t *testing.T) {
	id := testIdentity(t)
	now := time.Unix(1_800_000_000, 0)
	fingerprint, _ := identity.FingerprintPublicKey(id.PublicKey)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		token := issueCapabilityAt(t, id.ID, fingerprint, 2, now.Add(-2*time.Minute))
		_, _ = w.Write([]byte(`{"agent_admission":"` + token + `"}`))
	}))
	defer server.Close()
	client := Client{SupabaseURL: server.URL, PublishableKey: "public-test-key", HTTP: server.Client(), Now: func() time.Time { return now }}
	if _, err := client.Acquire(context.Background(), id, 2); err == nil {
		t.Fatal("expected expired capability to fail")
	}
}

func TestAcquireRejectsMissingTrustConfiguration(t *testing.T) {
	id := testIdentity(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request must not be sent without the public API key")
	}))
	defer server.Close()
	client := Client{SupabaseURL: server.URL}
	if _, err := client.Acquire(context.Background(), id, 1); err == nil {
		t.Fatal("expected missing publishable key to fail closed")
	}
	if err := (Client{SupabaseURL: "http://example.invalid", PublishableKey: "public-test-key"}).Validate(); err == nil {
		t.Fatal("expected non-loopback HTTP endpoint to fail")
	}
}

func TestAdmissionHTTPClientRequiresTLS13AndDisablesAmbientCredentials(t *testing.T) {
	client, err := (Client{}).httpClient("supabase.example")
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected a standard HTTP transport")
	}
	if transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		transport.TLSClientConfig.ServerName != "supabase.example" {
		t.Fatal("agent admission HTTP client must require TLS 1.3 and pin the configured server name")
	}
	if client.Jar != nil || client.CheckRedirect == nil {
		t.Fatal("agent admission HTTP client must disable cookies and redirects")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestAdmissionHTTPClientRejectsCustomTLSDialers(t *testing.T) {
	client := Client{HTTP: &http.Client{Transport: &http.Transport{
		DialTLS: func(string, string) (net.Conn, error) {
			return nil, errors.New("unexpected TLS dial")
		},
	}}}
	if _, err := client.httpClient("supabase.example"); err == nil {
		t.Fatal("expected custom TLS dialer to be rejected")
	}
}

func TestAdmissionHTTPClientRejectsCustomTransportThatCanBypassTLSPolicy(t *testing.T) {
	client := Client{HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unexpected request")
	})}}
	if _, err := client.httpClient("supabase.example"); err == nil {
		t.Fatal("expected custom transport to be rejected")
	}
}

func TestValidateEndpointResponseRequiresExactOriginAndTLS13(t *testing.T) {
	endpoint, err := url.Parse("https://supabase.example/functions/v1/agent-admission")
	if err != nil {
		t.Fatal(err)
	}
	responseURL := *endpoint
	response := &http.Response{
		Request: &http.Request{URL: &responseURL},
		TLS: &tls.ConnectionState{Version: tls.VersionTLS12, ServerName: "supabase.example"},
	}
	if err := validateEndpointResponse(response, endpoint); err == nil {
		t.Fatal("expected TLS 1.2 response to be rejected")
	}
	response.TLS.Version = tls.VersionTLS13
	if err := validateEndpointResponse(response, endpoint); err != nil {
		t.Fatalf("valid TLS 1.3 endpoint response rejected: %v", err)
	}
	wrongURL, _ := url.Parse("https://attacker.example/functions/v1/agent-admission")
	response.Request.URL = wrongURL
	if err := validateEndpointResponse(response, endpoint); err == nil {
		t.Fatal("expected response from another endpoint to be rejected")
	}
	response.Request.URL = &responseURL
	response.TLS.ServerName = "attacker.example"
	if err := validateEndpointResponse(response, endpoint); err == nil {
		t.Fatal("expected mismatched TLS server name to be rejected")
	}
}

func TestValidateEndpointResponseAllowsOnlyLoopbackHTTPForLocalTests(t *testing.T) {
	endpoint, err := url.Parse("http://127.0.0.1:8080/functions/v1/agent-admission")
	if err != nil {
		t.Fatal(err)
	}
	responseURL := *endpoint
	response := &http.Response{Request: &http.Request{URL: &responseURL}}
	if err := validateEndpointResponse(response, endpoint); err != nil {
		t.Fatalf("loopback HTTP response rejected: %v", err)
	}
	endpoint, _ = url.Parse("http://example.com/functions/v1/agent-admission")
	responseURL = *endpoint
	response.Request.URL = &responseURL
	if err := validateEndpointResponse(response, endpoint); err == nil {
		t.Fatal("expected non-loopback HTTP response to be rejected")
	}
}

func TestAcquireRejectsInvalidIdentityAndSlot(t *testing.T) {
	id := testIdentity(t)
	id.ID = "wd_aaaaaaaaaaaaaaaa"
	client := Client{SupabaseURL: "https://supabase.example", PublishableKey: "public-test-key"}
	if _, err := client.Acquire(context.Background(), id, 1); err == nil {
		t.Fatal("expected identity substitution to fail")
	}
	id = testIdentity(t)
	if _, err := client.Acquire(context.Background(), id, 0); err == nil {
		t.Fatal("expected invalid slot to fail")
	}
}

func issueCapability(t *testing.T, deviceID, fingerprint string, slot int, now time.Time) string {
	t.Helper()
	return issueCapabilityAt(t, deviceID, fingerprint, slot, now)
}

func issueCapabilityAt(t *testing.T, deviceID, fingerprint string, slot int, now time.Time) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "test-admission-key"})
	claims, _ := json.Marshal(capabilityClaims{
		Issuer: "wedecent-control-plane", Subject: deviceID, Audience: agentAudience,
		Purpose: agentPurpose, DeviceID: deviceID, PublicKeyFingerprint: fingerprint,
		Slot: slot, TokenID: "d90987bf-bae6-45da-ab21-c82d049617bd",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(90 * time.Second).Unix(),
	})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return input + "." + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
}

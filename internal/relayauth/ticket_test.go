package relayauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
)

func testIdentity() *identity.Identity {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &identity.Identity{ID: identity.DeviceID(pub), PublicKey: pub, PrivateKey: priv}
}

func TestIssueClientTicket(t *testing.T) {
	id := testIdentity()
	now := time.Unix(1_800_000_000, 0).UTC()
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	token, err := issue(id, "wd_4ksk5edkttwsxqx4", "client", 0, now, nonce)
	if err != nil {
		t.Fatal(err)
	}
	wantToken := "wdt2.eyJ2IjoyLCJhdWQiOiJ3ZWRlY2VudC1yZWxheSIsImlzcyI6IndkX213M2FtNDZ3NXdlZXg0YTQiLCJzdWIiOiJ3ZF80a3NrNWVka3R0d3N4cXg0Iiwicm9sZSI6ImNsaWVudCIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDkwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3IiwicGsiOiJlYlZXTG9fbVZQbEFlTEVTNkttTHA1QWZoVHJtbGI3WDRPT1JDNjBFbG1RIn0.DxjsYtag4atT2i07p591gAcmvjSd5IaXpVnEAGhRo1-uWY1CqynldMGlPczzyMWioTYLdZhzgMkqkpMfBihOCA"
	if token != wantToken {
		t.Fatalf("ticket wire format changed\ngot:  %s\nwant: %s", token, wantToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != TicketPrefix {
		t.Fatalf("unexpected token format: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Version != 2 || claims.Audience != TicketAudience || claims.Issuer != id.ID || claims.Subject != "wd_4ksk5edkttwsxqx4" || claims.Role != "client" || claims.Slot != 0 {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.IssuedAt != now.Unix() || claims.ExpiresAt != now.Add(TicketTTL).Unix() {
		t.Fatalf("unexpected ticket lifetime: %+v", claims)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(id.PublicKey, []byte(signingContext+parts[1]), sig) {
		t.Fatal("relay ticket signature did not verify")
	}
}

func TestAgentTicketMustBeSelfBound(t *testing.T) {
	id := testIdentity()
	if _, err := Issue(id, "wd_4ksk5edkttwsxqx4", "agent", 1, time.Now()); err == nil {
		t.Fatal("expected cross-device agent ticket to fail")
	}
	if _, err := Issue(id, id.ID, "agent", 0, time.Now()); err == nil {
		t.Fatal("expected invalid slot to fail")
	}
}

func TestAuthorizeTicketMustBeSelfBound(t *testing.T) {
	id := testIdentity()
	if _, err := Issue(id, "wd_4ksk5edkttwsxqx4", "authorize", 0, time.Now()); err == nil {
		t.Fatal("expected cross-device authorization ticket to fail")
	}
	if _, err := Issue(id, id.ID, "authorize", 1, time.Now()); err == nil {
		t.Fatal("expected authorization ticket with slot to fail")
	}
	if _, err := Issue(id, id.ID, "authorize", 0, time.Now()); err != nil {
		t.Fatalf("expected self-bound authorization ticket to succeed: %v", err)
	}
}

func TestClientTicketRejectsAgentSlot(t *testing.T) {
	id := testIdentity()
	if _, err := Issue(id, "wd_4ksk5edkttwsxqx4", "client", 1, time.Now()); err == nil {
		t.Fatal("expected client slot to fail")
	}
}

func TestRelayTimeURL(t *testing.T) {
	got, err := relayTimeURL("wss://relay.wedecent.com/v1/stream/wd_4ksk5edkttwsxqx4?role=client")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://relay.wedecent.com/v1/time" {
		t.Fatalf("got %q", got)
	}
}

func TestRelayNowCorrectsClockSkew(t *testing.T) {
	serverNow := time.Now().Add(8 * time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/time" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `{"unix_ms":%d}`, serverNow.UnixMilli())
	}))
	defer server.Close()

	got, err := relayNow(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if delta := got.Sub(serverNow); delta < -2*time.Second || delta > 2*time.Second {
		t.Fatalf("relay-adjusted time differs from server by %s", delta)
	}
}

func TestRelayNowRejectsAbsurdClockSkew(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"unix_ms":%d}`, time.Now().Add(25*time.Hour).UnixMilli())
	}))
	defer server.Close()

	if _, err := relayNow(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), "24h safety bound") {
		t.Fatalf("expected safety-bound error, got %v", err)
	}
}

func TestNewTicketSourceUsesRelayTime(t *testing.T) {
	id := testIdentity()
	serverNow := time.Now().Add(8 * time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"unix_ms":%d}`, serverNow.UnixMilli())
	}))
	defer server.Close()

	token, err := NewTicketSource(id)(context.Background(), server.URL, "wd_4ksk5edkttwsxqx4", "client", 0)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if delta := time.Unix(claims.IssuedAt, 0).Sub(serverNow); delta < -2*time.Second || delta > 2*time.Second {
		t.Fatalf("ticket issue time differs from relay by %s", delta)
	}
}

func TestRelayNowRejectsRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"unix_ms":%d}`, time.Now().UnixMilli())
	}))
	defer destination.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/v1/time", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	if _, err := relayNow(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), "Temporary Redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

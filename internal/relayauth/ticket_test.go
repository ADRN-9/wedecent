package relayauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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

func TestClientTicketRejectsAgentSlot(t *testing.T) {
	id := testIdentity()
	if _, err := Issue(id, "wd_4ksk5edkttwsxqx4", "client", 1, time.Now()); err == nil {
		t.Fatal("expected client slot to fail")
	}
}

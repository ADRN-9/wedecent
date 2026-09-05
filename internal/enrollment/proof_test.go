package enrollment

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestMessageCanonical(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	pub := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	got, err := Message(ProofFields{
		ChallengeID:   "123e4567-e89b-42d3-a456-426614174000",
		Challenge:     challenge,
		UserID:        "0b7729e9-95bf-4591-80f4-3f0616e57751",
		DeviceID:      "wd_aaaaaaaaaaaaaaaa",
		PublicKey:     pub,
		Kind:          "agent",
		ExpiresUnixMS: 1787760000000,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{
		"wedecent-enrollment-v1\n",
		"organization_id=-\n",
		"expires_unix_ms=1787760000000\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("message missing %q: %q", want, text)
		}
	}
}

func TestMessageRejectsBadChallenge(t *testing.T) {
	_, err := Message(ProofFields{
		ChallengeID:   "123e4567-e89b-42d3-a456-426614174000",
		Challenge:     "bad",
		UserID:        "0b7729e9-95bf-4591-80f4-3f0616e57751",
		DeviceID:      "wd_aaaaaaaaaaaaaaaa",
		PublicKey:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Kind:          "agent",
		ExpiresUnixMS: 1,
	})
	if err == nil {
		t.Fatal("expected invalid challenge error")
	}
}

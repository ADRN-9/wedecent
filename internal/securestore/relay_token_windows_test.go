//go:build windows

package securestore

import (
	"bytes"
	"os"
	"testing"
)

func TestRelayTokenRoundTrip(t *testing.T) {
	state := t.TempDir()
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := StoreRelayToken(state, token); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(RelayTokenPath(state))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(token)) {
		t.Fatal("protected credential contains plaintext token")
	}
	got, err := LoadRelayToken(state)
	if err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Fatalf("got %q, want original token", got)
	}
}

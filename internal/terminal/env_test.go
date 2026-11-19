package terminal

import (
	"strings"
	"testing"
)

func TestChildEnvironmentDoesNotInheritPairingSecret(t *testing.T) {
	t.Setenv("WEDECENT_PAIRING_SECRET", "canary-pairing-secret")
	t.Setenv("TERM", "parent-term")

	env := childEnvironment("TERM=xterm-256color")
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "WEDECENT_PAIRING_SECRET") {
			t.Fatalf("child environment leaked pairing secret: %q", entry)
		}
		if strings.EqualFold(name, "TERM") && entry != "TERM=xterm-256color" {
			t.Fatalf("unexpected inherited TERM entry: %q", entry)
		}
	}
}

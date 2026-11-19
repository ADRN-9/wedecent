package processenv

import (
	"reflect"
	"strings"
	"testing"
)

func TestWithoutPairingSecretRemovesEveryCaseInsensitiveEntry(t *testing.T) {
	input := []string{
		"PATH=/usr/bin",
		"WEDECENT_PAIRING_SECRET=first-canary",
		"wedecent_pairing_secret=second-canary",
		"TERM=xterm",
	}
	got := WithoutPairingSecret(input)
	want := []string{"PATH=/usr/bin", "TERM=xterm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WithoutPairingSecret() = %#v, want %#v", got, want)
	}
}

func TestClearCurrentRemovesPairingSecret(t *testing.T) {
	t.Setenv(PairingSecretVariable, "process-canary")
	t.Setenv(strings.ToLower(PairingSecretVariable), "lowercase-canary")
	ClearCurrent()
	for _, entry := range Current() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, PairingSecretVariable) {
			t.Fatalf("ClearCurrent() left pairing secret variable %q in the process environment", name)
		}
	}
}

func TestCurrentDoesNotExposePairingSecret(t *testing.T) {
	t.Setenv(PairingSecretVariable, "process-canary")
	for _, entry := range Current() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, PairingSecretVariable) {
			t.Fatalf("Current() leaked pairing secret environment entry %q", entry)
		}
	}
}

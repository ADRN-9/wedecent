package processenv

import (
	"os"
	"os/exec"
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

func TestClearCurrentRemovesPairingSecretFromDescendantProcess(t *testing.T) {
	if os.Getenv("WEDECENT_PROCESSENV_CLEAR_HELPER") == "1" {
		ClearCurrent()
		cmd := exec.Command(os.Args[0], "-test.run=^TestPairingSecretAbsentInGrandchild$")
		cmd.Env = append(os.Environ(), "WEDECENT_PROCESSENV_GRANDCHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("grandchild inherited a cleared pairing secret: %v: %s", err, output)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestClearCurrentRemovesPairingSecretFromDescendantProcess$")
	cmd.Env = append(
		WithoutPairingSecret(os.Environ()),
		PairingSecretVariable+"=parent-canary",
		strings.ToLower(PairingSecretVariable)+"=lowercase-canary",
		"WEDECENT_PROCESSENV_CLEAR_HELPER=1",
		"WEDECENT_PROCESSENV_KEEP=preserved",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subprocess pairing-secret isolation failed: %v: %s", err, output)
	}
}

func TestPairingSecretAbsentInGrandchild(t *testing.T) {
	if os.Getenv("WEDECENT_PROCESSENV_GRANDCHILD") != "1" {
		return
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, PairingSecretVariable) {
			t.Fatalf("pairing secret reached descendant process through %q", name)
		}
	}
	if os.Getenv("WEDECENT_PROCESSENV_KEEP") != "preserved" {
		t.Fatal("pairing-secret filtering removed unrelated process environment")
	}
}

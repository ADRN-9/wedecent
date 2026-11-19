package processenv

import (
	"os"
	"strings"
)

const PairingSecretVariable = "WEDECENT_PAIRING_SECRET"

func WithoutPairingSecret(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, PairingSecretVariable) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func Current() []string {
	return WithoutPairingSecret(os.Environ())
}

func ClearCurrent() {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, PairingSecretVariable) {
			_ = os.Unsetenv(name)
		}
	}
}

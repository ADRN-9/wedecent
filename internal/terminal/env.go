package terminal

import (
	"os"
	"strings"

	"wedecent.com/wedecent/internal/processenv"
)

func childEnvironment(extra ...string) []string {
	inherited := processenv.WithoutPairingSecret(os.Environ())
	filtered := make([]string, 0, len(inherited)+len(extra))
	for _, entry := range inherited {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "TERM") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, extra...)
}

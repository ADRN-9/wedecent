package terminal

import (
	"os"
	"strings"
)

func childEnvironment(extra ...string) []string {
	inherited := os.Environ()
	filtered := make([]string, 0, len(inherited)+len(extra))
	for _, entry := range inherited {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "WEDECENT_PAIRING_SECRET") || strings.EqualFold(name, "TERM") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, extra...)
}

package appdirs

import (
	"fmt"
	"os"
	"path/filepath"
)

func Client() (string, error) { return roleDir("client") }
func Agent() (string, error)  { return roleDir("agent") }
func Core() (string, error)   { return roleDir("core") }

func roleDir(role string) (string, error) {
	if base := os.Getenv("WEDECENT_HOME"); base != "" {
		return filepath.Join(base, role), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".wedecent", role), nil
}

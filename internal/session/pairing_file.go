package session

import (
	"os"
	"path/filepath"
)

func invalidatePairingSecret(stateDir string) error {
	path := filepath.Join(stateDir, "pairing-secret.sha256")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

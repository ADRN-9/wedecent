//go:build windows

package main

import (
	"fmt"
	"os"

	"wedecent.com/wedecent/internal/trust"
)

// Validate the state ACL before writing or loading any agent identity material.
func preflightAgentState(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("prepare agent state directory: %w", err)
	}
	if err := trust.VerifyPairingStatePath(dir); err != nil {
		return fmt.Errorf("agent state security preflight: %w", err)
	}
	return nil
}

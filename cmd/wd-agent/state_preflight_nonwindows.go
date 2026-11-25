//go:build !windows

package main

// Retain Unix identity directory creation and permission-repair semantics.
func preflightAgentState(string) error {
	return nil
}

func verifyMigrationStateParent(string) error {
	return errors.New("Windows migration state verification is unsupported on this platform")
}

func verifyMigrationStateForSID(string, string) error {
	return errors.New("Windows migration state verification is unsupported on this platform")
}

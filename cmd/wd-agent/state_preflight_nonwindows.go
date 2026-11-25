//go:build !windows

package main

import "errors"

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

func verifyMigrationParentForProvisioning(string) error {
	return errors.New("Windows migration parent verification is unsupported on this platform")
}

func verifyMigrationSourceForSID(string, string) error {
	return errors.New("Windows legacy migration source verification is unsupported on this platform")
}

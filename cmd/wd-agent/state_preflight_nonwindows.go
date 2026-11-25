//go:build !windows

package main

// Retain Unix identity directory creation and permission-repair semantics.
func preflightAgentState(string) error {
	return nil
}

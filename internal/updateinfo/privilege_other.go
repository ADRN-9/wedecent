//go:build !windows

package updateinfo

// The PowerShell executor is exercised with process fixtures on non-Windows
// hosts; Windows production builds use the real token elevation check.
func currentProcessElevated() bool { return false }

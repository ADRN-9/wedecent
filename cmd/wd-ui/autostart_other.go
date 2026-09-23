//go:build !windows

package main

func platformEnableAutostart() error {
	return ErrAutostartUnsupported
}

func platformDisableAutostart() error {
	return ErrAutostartUnsupported
}

func platformAutostartStatus() (autostartStatus, error) {
	return "", ErrAutostartUnsupported
}

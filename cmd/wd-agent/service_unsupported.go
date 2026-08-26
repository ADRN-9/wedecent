//go:build !windows

package main

import "errors"

func runServiceCommand([]string) error {
	return errors.New("native service management is only available on Windows")
}

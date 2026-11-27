//go:build !windows

package main

import "errors"

func runUpdateCommand([]string) error {
	return errors.New("the privileged stable updater is supported only on Windows")
}

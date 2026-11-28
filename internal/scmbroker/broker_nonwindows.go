//go:build !windows

package scmbroker

import "errors"

var ErrUnsupported = errors.New("SCM broker is supported only on Windows")

func Run() error { return ErrUnsupported }
func InstallService(string) error { return ErrUnsupported }
func UninstallService() error { return ErrUnsupported }

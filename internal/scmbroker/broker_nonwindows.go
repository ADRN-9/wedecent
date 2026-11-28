//go:build !windows

package scmbroker

import "errors"

var ErrUnsupported = errors.New("SCM broker is supported only on Windows")

func Run() error { return ErrUnsupported }

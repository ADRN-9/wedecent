package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	ErrAutostartUnsupported = errors.New("wd-ui autostart is only supported on Windows")
	ErrAutostartUsage       = errors.New("usage: wd-ui autostart <enable|disable|status>")
	ErrAutostartExecutable  = errors.New("wd-ui autostart executable is unavailable")
)

type autostartStatus string

const (
	autostartStatusEnabled  autostartStatus = "enabled"
	autostartStatusDisabled autostartStatus = "disabled"
	autostartStatusStale    autostartStatus = "stale"
)

type autostartStore interface {
	Get() (value string, present bool, err error)
	Set(value string) error
	Delete() error
}

type autostartExecutableFunc func() (string, error)

func runAutostartCommand(args []string, out io.Writer) error {
	if len(args) != 1 {
		return ErrAutostartUsage
	}
	if out == nil {
		return errors.New("autostart output is required")
	}

	var (
		status autostartStatus
		err    error
	)
	switch args[0] {
	case "enable":
		err = platformEnableAutostart()
		status = autostartStatusEnabled
	case "disable":
		err = platformDisableAutostart()
		status = autostartStatusDisabled
	case "status":
		status, err = platformAutostartStatus()
	default:
		return ErrAutostartUsage
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, status)
	return err
}

func enableAutostartWith(store autostartStore, executable autostartExecutableFunc) error {
	if store == nil || executable == nil {
		return ErrAutostartExecutable
	}
	path, err := executable()
	if err != nil {
		return err
	}
	command, err := autostartCommandLine(path)
	if err != nil {
		return err
	}
	return store.Set(command)
}

func disableAutostartWith(store autostartStore) error {
	if store == nil {
		return ErrAutostartExecutable
	}
	return store.Delete()
}

func autostartStatusWith(store autostartStore, executable autostartExecutableFunc) (autostartStatus, error) {
	if store == nil || executable == nil {
		return "", ErrAutostartExecutable
	}
	value, present, err := store.Get()
	if err != nil {
		return "", err
	}
	if !present {
		return autostartStatusDisabled, nil
	}
	path, err := executable()
	if err != nil {
		return "", err
	}
	command, err := autostartCommandLine(path)
	if err != nil {
		return "", err
	}
	if value == command {
		return autostartStatusEnabled, nil
	}
	return autostartStatusStale, nil
}

func autostartCommandLine(executable string) (string, error) {
	if strings.TrimSpace(executable) == "" || strings.ContainsAny(executable, "\x00\r\n\"") {
		return "", ErrAutostartExecutable
	}
	return `"` + executable + `"`, nil
}

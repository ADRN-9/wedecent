//go:build !windows

package winservice

import (
	"context"
	"errors"
)

var errWindowsOnly = errors.New("Windows service support is only available on Windows")

type InstallOptions struct {
	Name        string
	DisplayName string
	Description string
	Account     string
	Password    string
	Executable  string
	Arguments   []string
	Automatic   bool
}

type Status struct {
	State     string
	ProcessID uint32
	ExitCode  uint32
}

func Install(InstallOptions) error                  { return errWindowsOnly }
func Start(string) error                            { return errWindowsOnly }
func Stop(string) error                             { return errWindowsOnly }
func Uninstall(string) error                        { return errWindowsOnly }
func Query(string) (Status, error)                  { return Status{}, errWindowsOnly }
func Run(string, func(context.Context) error) error { return errWindowsOnly }
func RestrictDirectory(string, string) error        { return errWindowsOnly }

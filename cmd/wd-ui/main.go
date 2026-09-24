package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"wedecent.com/wedecent/internal/buildinfo"
	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/guiapp"
)

var errUIUsage = errors.New("usage: wd-ui [version|autostart <enable|disable|status>|update-key status]")

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			if len(os.Args) != 2 {
				exitCLI(errUIUsage, 2)
			}
			if err := buildinfo.Write(os.Stdout, "wd-ui"); err != nil {
				exitCLI(fmt.Errorf("version: %w", err), 1)
			}
			return
		case "autostart":
			if err := runAutostartCommand(os.Args[2:], os.Stdout); err != nil {
				code := 1
				if errors.Is(err, ErrAutostartUsage) {
					code = 2
				}
				exitCLI(err, code)
			}
			return
		case "update-key":
			if err := runUpdateKeyCommand(os.Args[2:], os.Stdout); err != nil {
				code := 1
				if errors.Is(err, ErrUpdateKeyUsage) {
					code = 2
				}
				exitCLI(err, code)
			}
			return
		default:
			exitCLI(errUIUsage, 2)
		}
	}

	core, err := coreclient.New(coreclient.Config{})
	if err != nil {
		showFatal(err)
		os.Exit(1)
	}
	uiCore, err := prepareLocalCore(context.Background(), core)
	if err != nil {
		showFatal(err)
		os.Exit(1)
	}
	controller, err := guiapp.New(uiCore)
	if err != nil {
		showFatal(err)
		os.Exit(1)
	}
	if err := runUI(controller); err != nil {
		showFatal(err)
		os.Exit(1)
	}
}

func exitCLI(err error, code int) {
	fmt.Fprintln(os.Stderr, "wd-ui:", err)
	os.Exit(code)
}

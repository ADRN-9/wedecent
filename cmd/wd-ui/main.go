package main

import (
	"context"
	"fmt"
	"os"

	"wedecent.com/wedecent/internal/buildinfo"
	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/guiapp"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		if err := buildinfo.Write(os.Stdout, "wd-ui"); err != nil {
			showFatal(fmt.Errorf("version: %w", err))
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		showFatal(fmt.Errorf("usage: wd-ui"))
		os.Exit(2)
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

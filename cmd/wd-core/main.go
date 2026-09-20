package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/buildinfo"
	"wedecent.com/wedecent/internal/coreapi/coreprocess"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		if err := buildinfo.Write(os.Stdout, "wd-core"); err != nil {
			fmt.Fprintln(os.Stderr, "wd-core:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "wd-core:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	state, err := appdirs.Client()
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("wd-core", flag.ContinueOnError)
	clientStateDir := fs.String("state", state, "existing client state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd-core [--state directory]")
	}

	server, err := coreprocess.OpenReadOnly(*clientStateDir)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return coreprocess.RunLocal(ctx, server)
}

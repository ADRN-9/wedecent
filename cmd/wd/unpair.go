package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/trust"
)

func runUnpair(args []string) error {
	state, err := appdirs.Client()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("unpair", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: wd unpair [--state directory] <device-id>")
	}

	peer, err := trust.Revoke(filepath.Join(*stateDir, "trusted-devices.json"), fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Printf("Removed local trust for %s (%s)\n", peer.ID, peer.Name)
	fmt.Println("Remote client authorization is unchanged; revoke this client on the device separately if bidirectional trust removal is required.")
	return nil
}

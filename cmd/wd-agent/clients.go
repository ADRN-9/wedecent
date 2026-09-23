package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sort"

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/trust"
)

func runClients(args []string) error {
	if len(args) == 0 {
		return runClientsList(nil)
	}
	switch args[0] {
	case "list":
		return runClientsList(args[1:])
	case "revoke":
		return runClientsRevoke(args[1:])
	default:
		return fmt.Errorf("unknown clients command %q; use list or revoke", args[0])
	}
}

func runClientsList(args []string) error {
	state, err := appdirs.Agent()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("clients list", flag.ContinueOnError)
	stateDir := fs.String("state", state, "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd-agent clients list [--state directory]")
	}
	store, err := trust.Open(filepath.Join(*stateDir, "trusted-clients.json"))
	if err != nil {
		return err
	}
	peers := store.List()
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	for _, peer := range peers {
		fmt.Printf("%s\t%s\t%s\n", peer.ID, peer.Name, peer.Fingerprint)
	}
	return nil
}

func runClientsRevoke(args []string) error {
	state, err := appdirs.Agent()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("clients revoke", flag.ContinueOnError)
	stateDir := fs.String("state", state, "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: wd-agent clients revoke [--state directory] <client-id>")
	}
	peer, err := trust.Revoke(filepath.Join(*stateDir, "trusted-clients.json"), fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Printf("Revoked client %s (%s)\n", peer.ID, peer.Name)
	fmt.Println("New sessions are denied immediately; already-established sessions are not terminated.")
	return nil
}

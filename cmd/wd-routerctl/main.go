package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/buildinfo"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/routercontrol"
	"wedecent.com/wedecent/internal/trust"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		if err := buildinfo.Write(os.Stdout, "wd-routerctl"); err != nil {
			fmt.Fprintln(os.Stderr, "wd-routerctl:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "wd-routerctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	stateDir, err := appdirs.Agent()
	if err != nil {
		return err
	}

	switch args[0] {
	case "trust":
		return runTrust(stateDir, args[1:])
	case "revoke":
		return runRevoke(stateDir, args[1:])
	case "list":
		return runList(stateDir, args[1:])
	default:
		return usageError()
	}
}

func runTrust(defaultStateDir string, args []string) error {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	stateDir := fs.String("state", defaultStateDir, "agent state directory")
	id := fs.String("id", "", "controller device ID")
	name := fs.String("name", "Local Core", "controller display name")
	fingerprint := fs.String("fingerprint", "", "controller public-key fingerprint")
	replace := fs.Bool("replace", false, "replace an existing controller fingerprint for this ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd-routerctl trust [--state directory] --id device-id --fingerprint SHA256:hex [--name name] [--replace]")
	}

	controllerID := strings.TrimSpace(*id)
	if controllerID == "" {
		return errors.New("controller device ID is required")
	}
	canonicalFingerprint, err := identity.ParseFingerprint(*fingerprint)
	if err != nil {
		return fmt.Errorf("invalid controller fingerprint: %w", err)
	}

	store, err := routercontrol.OpenControllerTrust(*stateDir)
	if err != nil {
		return err
	}
	if existing, ok := store.Get(controllerID); ok &&
		existing.Fingerprint != canonicalFingerprint && !*replace {
		return errors.New("controller ID already has a different fingerprint; use --replace for an intentional key rotation")
	}
	if existing, ok := store.FindByFingerprint(canonicalFingerprint); ok && existing.ID != controllerID {
		return errors.New("controller fingerprint is already trusted under a different device ID")
	}

	displayName := identity.SanitizeName(*name)
	if displayName == "" {
		displayName = controllerID
	}
	if err := store.Put(trust.Peer{
		ID:          controllerID,
		Name:        displayName,
		Fingerprint: canonicalFingerprint,
	}); err != nil {
		return fmt.Errorf("store router controller trust: %w", err)
	}
	fmt.Printf("Trusted router controller %s %s\n", controllerID, canonicalFingerprint)
	return nil
}

func runRevoke(defaultStateDir string, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	stateDir := fs.String("state", defaultStateDir, "agent state directory")
	id := fs.String("id", "", "controller device ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd-routerctl revoke [--state directory] --id device-id")
	}
	controllerID := strings.TrimSpace(*id)
	if controllerID == "" {
		return errors.New("controller device ID is required")
	}

	store, err := routercontrol.OpenControllerTrust(*stateDir)
	if err != nil {
		return err
	}
	removed, err := store.Delete(controllerID)
	if err != nil {
		return fmt.Errorf("revoke router controller trust: %w", err)
	}
	if !removed {
		return errors.New("router controller is not trusted")
	}
	fmt.Printf("Revoked router controller %s\n", controllerID)
	return nil
}

func runList(defaultStateDir string, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	stateDir := fs.String("state", defaultStateDir, "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd-routerctl list [--state directory]")
	}

	store, err := routercontrol.OpenControllerTrust(*stateDir)
	if err != nil {
		return err
	}
	peers := store.List()
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].ID < peers[j].ID
	})
	for _, peer := range peers {
		fmt.Printf("%s\t%s\t%s\n", peer.ID, peer.Name, peer.Fingerprint)
	}
	return nil
}

func usageError() error {
	return errors.New("usage: wd-routerctl <trust|revoke|list> [options]")
}

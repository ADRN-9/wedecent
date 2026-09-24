package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/audit"
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
	auditLog, err := audit.Open(*stateDir)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	event := audit.Event{Type: "router.controller_trust", Outcome: "attempt", PeerID: controllerID}
	if *replace {
		event.Reason = "replace"
	}
	if err := auditLog.Append(event); err != nil {
		return fmt.Errorf("audit controller trust attempt: %w", err)
	}

	store, err := routercontrol.OpenControllerTrust(*stateDir)
	if err != nil {
		appendRouterAdminAudit(auditLog, event, "failed", "trust_store_open_failed")
		return err
	}
	if existing, ok := store.Get(controllerID); ok &&
		existing.Fingerprint != canonicalFingerprint && !*replace {
		appendRouterAdminAudit(auditLog, event, "denied", "replacement_required")
		return errors.New("controller ID already has a different fingerprint; use --replace for an intentional key rotation")
	}
	if existing, ok := store.FindByFingerprint(canonicalFingerprint); ok && existing.ID != controllerID {
		appendRouterAdminAudit(auditLog, event, "denied", "fingerprint_alias")
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
		appendRouterAdminAudit(auditLog, event, "failed", "trust_store_update_failed")
		return fmt.Errorf("store router controller trust: %w", err)
	}
	if err := appendRouterAdminAudit(auditLog, event, "success", ""); err != nil {
		return fmt.Errorf("router controller %s was trusted, but the audit success event could not be persisted: %w", controllerID, err)
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
	auditLog, err := audit.Open(*stateDir)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	event := audit.Event{Type: "router.controller_revoke", Outcome: "attempt", PeerID: controllerID}
	if err := auditLog.Append(event); err != nil {
		return fmt.Errorf("audit controller revoke attempt: %w", err)
	}

	store, err := routercontrol.OpenControllerTrust(*stateDir)
	if err != nil {
		appendRouterAdminAudit(auditLog, event, "failed", "trust_store_open_failed")
		return err
	}
	removed, err := store.Delete(controllerID)
	if err != nil {
		appendRouterAdminAudit(auditLog, event, "failed", "trust_store_update_failed")
		return fmt.Errorf("revoke router controller trust: %w", err)
	}
	if !removed {
		appendRouterAdminAudit(auditLog, event, "denied", "controller_not_trusted")
		return errors.New("router controller is not trusted")
	}
	if err := appendRouterAdminAudit(auditLog, event, "success", ""); err != nil {
		return fmt.Errorf("router controller %s was revoked, but the audit success event could not be persisted: %w", controllerID, err)
	}
	fmt.Printf("Revoked router controller %s\n", controllerID)
	return nil
}

func appendRouterAdminAudit(log *audit.Log, base audit.Event, outcome, reason string) error {
	base.Outcome = outcome
	base.Reason = reason
	return log.Append(base)
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

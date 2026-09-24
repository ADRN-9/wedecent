package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/audit"
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

	deviceID := fs.Arg(0)
	auditLog, err := audit.Open(*stateDir)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	if err := auditLog.Append(audit.Event{Type: "trust.device_unpair", Outcome: "attempt", PeerID: deviceID}); err != nil {
		return fmt.Errorf("audit device unpair attempt: %w", err)
	}

	peer, err := trust.Revoke(filepath.Join(*stateDir, "trusted-devices.json"), deviceID)
	if err != nil {
		_ = auditLog.Append(audit.Event{Type: "trust.device_unpair", Outcome: "failed", PeerID: deviceID, Reason: "trust_store_update_failed"})
		return err
	}
	if err := auditLog.Append(audit.Event{Type: "trust.device_unpair", Outcome: "success", PeerID: peer.ID}); err != nil {
		return fmt.Errorf("device %s was unpaired, but the audit success event could not be persisted: %w", peer.ID, err)
	}
	fmt.Printf("Removed local trust for %s (%s)\n", peer.ID, peer.Name)
	fmt.Println("Remote client authorization is unchanged; revoke this client on the device separately if bidirectional trust removal is required.")
	return nil
}

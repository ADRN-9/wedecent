package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/trust"
)

const (
	PairingRecoveryConfirmed = "confirmed"
	PairingRecoveryVisibleUnconfirmed = "trust_visible_unconfirmed"
	PairingRecoveryUnresolved = "unresolved"
	PairingRecoveryConflict = "trust_conflict"
	PairingRecoveryDenied = "denied"
)

type PairingRecoveryAssessment struct {
	Audit audit.PairingOutcome
	Status string
}

// InspectPairingRecovery is read-only; no visible record proves durability
// without an explicitly confirmed completion marker. An unreadable trust store
// aborts inspection rather than fabricating absent or successful trust.
func InspectPairingRecovery(stateDir string) ([]PairingRecoveryAssessment, error) {
	recovery, err := audit.OpenPairingRecovery(stateDir)
	if err != nil {
		return nil, err
	}
	records, err := recovery.Records()
	if err != nil {
		return nil, err
	}
	trustPath := filepath.Join(stateDir, "trusted-clients.json")
	if _, statErr := os.Lstat(trustPath); statErr == nil {
		if err := trust.VerifyPairingStatePath(trustPath); err != nil {
			return nil, fmt.Errorf("unsafe authoritative pairing trust: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	fresh, err := trust.Open(trustPath)
	if err != nil {
		return nil, fmt.Errorf("read authoritative pairing trust: %w", err)
	}
	result := make([]PairingRecoveryAssessment, 0, len(records))
	for _, record := range records {
		stored, found := fresh.Peers[record.PeerID]
		status := PairingRecoveryUnresolved
		switch {
		case found && stored.Fingerprint != record.Fingerprint:
			status = PairingRecoveryConflict
		case record.Outcome == audit.PairingOutcomeSuccess && found:
			status = PairingRecoveryConfirmed
		case found:
			status = PairingRecoveryVisibleUnconfirmed
		case record.Outcome == audit.PairingOutcomeDenied:
			status = PairingRecoveryDenied
		}
		result = append(result, PairingRecoveryAssessment{Audit: record, Status: status})
	}
	return result, nil
}

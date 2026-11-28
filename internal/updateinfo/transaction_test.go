package updateinfo

import "testing"

func transactionStateFixture() State {
	transaction := &InstallTransaction{
		ID:              "0123456789abcdef0123456789abcdef",
		Sequence:        11,
		ManifestDigest:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PackageDigest:   "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PreviousVersion: "v1.0.0",
		TargetVersion:   "v1.1.0",
		Phase:           InstallPhasePending,
	}
	return State{
		Version:          UpdateStateVersionWithInstall,
		StableSequence:   10,
		KeysetEpoch:      1,
		KeysetDigest:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		InstalledVersion: "v1.0.0",
		PendingInstall:   transaction,
	}
}

func TestInstallStateTransitionsRequireAtomicCommit(t *testing.T) {
	pending := transactionStateFixture()
	executing := pending
	executing.PendingInstall = cloneInstallTransaction(pending.PendingInstall)
	executing.PendingInstall.Phase = InstallPhaseExecuting
	committed := executing
	committed.PendingInstall = cloneInstallTransaction(executing.PendingInstall)
	committed.PendingInstall.Phase = InstallPhaseCommitted
	final := committed
	final.PendingInstall = nil
	final.StableSequence = 11
	final.InstalledVersion = "v1.1.0"

	for name, pair := range map[string][2]State{
		"pending to executing":          {pending, executing},
		"executing to committed":        {executing, committed},
		"committed to final atomically": {committed, final},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateInstallStateTransition(pair[0], pair[1]); err != nil {
				t.Fatalf("valid transition rejected: %v", err)
			}
		})
	}
}

func TestInstallStateTransitionsRejectReplayAndInconsistentState(t *testing.T) {
	pending := transactionStateFixture()
	executing := pending
	executing.PendingInstall = cloneInstallTransaction(pending.PendingInstall)
	executing.PendingInstall.Phase = InstallPhaseExecuting
	committed := executing
	committed.PendingInstall = cloneInstallTransaction(executing.PendingInstall)
	committed.PendingInstall.Phase = InstallPhaseCommitted

	tests := map[string]State{
		"skip execution": func() State {
			state := committed
			state.PendingInstall = cloneInstallTransaction(committed.PendingInstall)
			return state
		}(),
		"mutated transaction digest": func() State {
			state := executing
			state.PendingInstall = cloneInstallTransaction(executing.PendingInstall)
			state.PendingInstall.PackageDigest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			return state
		}(),
		"sequence advanced before commit": func() State {
			state := executing
			state.StableSequence = 11
			return state
		}(),
		"cleared before commit": func() State {
			state := executing
			state.PendingInstall = nil
			return state
		}(),
		"unknown phase": func() State {
			state := pending
			state.PendingInstall = cloneInstallTransaction(pending.PendingInstall)
			state.PendingInstall.Phase = "unknown"
			return state
		}(),
	}
	for name, next := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateInstallStateTransition(pending, next); err == nil {
				t.Fatal("inconsistent transaction transition was accepted")
			}
		})
	}
}

func TestInstallRecoveryCanClearOnlyAfterVerifiedOutcome(t *testing.T) {
	executing := transactionStateFixture()
	executing.PendingInstall.Phase = InstallPhaseExecuting
	recovery := executing
	recovery.PendingInstall = cloneInstallTransaction(executing.PendingInstall)
	recovery.PendingInstall.Phase = InstallPhaseRecoveryRequired

	restored := recovery
	restored.PendingInstall = nil
	if err := validateInstallStateTransition(recovery, restored); err != nil {
		t.Fatalf("verified restoration transition rejected: %v", err)
	}

	applied := recovery
	applied.PendingInstall = nil
	applied.StableSequence = 11
	applied.InstalledVersion = "v1.1.0"
	if err := validateInstallStateTransition(recovery, applied); err != nil {
		t.Fatalf("verified applied transition rejected: %v", err)
	}

	ambiguous := recovery
	ambiguous.PendingInstall = nil
	ambiguous.StableSequence = 11
	if err := validateInstallStateTransition(recovery, ambiguous); err == nil {
		t.Fatal("ambiguous recovery cleared the transaction")
	}
}

func cloneInstallTransaction(transaction *InstallTransaction) *InstallTransaction {
	if transaction == nil {
		return nil
	}
	copy := *transaction
	return &copy
}

func TestPersistedPendingInstallMustMatchInstalledVersion(t *testing.T) {
	state := transactionStateFixture()
	state.PendingInstall.PreviousVersion = "v0.9.9"
	if err := state.validatePersisted(); err == nil {
		t.Fatal("persisted transaction with mismatched previous version was accepted")
	}
}

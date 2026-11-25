package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resolvePairingWithProof(t *testing.T, dir string, recovery *PairingRecovery, id, outcome string) {
	t.Helper()
	if err := recovery.Complete(id, outcome); err != nil { t.Fatal(err) }
	event := Event{Time:time.Now().UTC(), ActorID:testPairingActor, PeerID:testPairingPeer, AttemptID:id}
	if outcome == PairingOutcomeSuccess {
		event.Type, event.Outcome = "pairing.trust_added", "success"
	} else {
		event.Type, event.Outcome = "pairing.request", "denied"
	}
	log, err := Open(dir)
	if err != nil { t.Fatal(err) }
	if err := log.Append(event); err != nil { t.Fatal(err) }
	if err := recovery.ConfirmCompletion(log, id, event); err != nil { t.Fatal(err) }
}

func resolveAndAcknowledgePairing(t *testing.T, dir string, recovery *PairingRecovery, id, outcome string) {
	t.Helper()
	resolvePairingWithProof(t, dir, recovery, id, outcome)
	if err := recovery.AcknowledgeResolved(id); err != nil { t.Fatal(err) }
}

func TestPairingRecoveryArchivesOnlyContiguousVerifiedResolvedPrefix(t *testing.T) {
	dir := recoveryTestDir(t)
	recovery, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, second := strings.Repeat("1", 32), strings.Repeat("2", 32)
	if err := recovery.Begin(testRecoveryRecord(first)); err != nil {
		t.Fatal(err)
	}
	if err := recovery.Begin(testRecoveryRecord(second)); err != nil {
		t.Fatal(err)
	}
	resolveAndAcknowledgePairing(t, dir, recovery, second, PairingOutcomeSuccess)
	if err := recovery.CompactResolved(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, pairingArchiveFileName)); !os.IsNotExist(err) {
		t.Fatal("later resolved record bypassed earlier unresolved record")
	}
	resolveAndAcknowledgePairing(t, dir, recovery, first, PairingOutcomeDenied)
	if err := recovery.CompactResolved(); err != nil {
		t.Fatal(err)
	}
	archive, err := recovery.readArchive()
	if err != nil {
		t.Fatal(err)
	}
	if archive.LastSequence != 2 || len(archive.Records) != 2 {
		t.Fatalf("archive checkpoint invalid: %+v", archive)
	}
	all, err := recovery.Records()
	if err != nil || len(all) != 2 {
		t.Fatalf("archived evidence not visible through Records: %d %v", len(all), err)
	}
	snapshot, err := recovery.read()
	if err != nil || len(snapshot.Records) != 0 || snapshot.ArchivedThrough != 2 {
		t.Fatalf("active ledger not compacted: %+v %v", snapshot, err)
	}
}

func TestPairingRecoveryArchiveInterruptedCompactionReconciles(t *testing.T) {
	dir := recoveryTestDir(t)
	recovery, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("3", 32)
	if err := recovery.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	resolvePairingWithProof(t, dir, recovery, id, PairingOutcomeSuccess)
	recovery.archiveAfterSync = func() error { return os.ErrPermission }
	if err := recovery.AcknowledgeResolved(id); err == nil {
		t.Fatal("injected archive/compaction interruption was ignored")
	}
	restarted, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := restarted.read()
	if err != nil || len(snapshot.Records) != 0 || snapshot.ArchivedThrough != 1 {
		t.Fatalf("restart did not reconcile durable archive before compaction: %+v %v", snapshot, err)
	}
	all, err := restarted.Records()
	if err != nil || len(all) != 1 || all[0].AttemptID != id {
		t.Fatalf("archived evidence lost: %+v %v", all, err)
	}
}

func TestPairingRecoveryArchiveAuthenticationAndSequenceFailClosed(t *testing.T) {
	t.Run("archive-tamper", func(t *testing.T) {
		dir := recoveryTestDir(t)
		recovery, err := OpenPairingRecovery(dir)
		if err != nil {
			t.Fatal(err)
		}
		id := strings.Repeat("4", 32)
		if err := recovery.Begin(testRecoveryRecord(id)); err != nil {
			t.Fatal(err)
		}
		resolveAndAcknowledgePairing(t, dir, recovery, id, PairingOutcomeSuccess)
		if err := recovery.CompactResolved(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, pairingArchiveFileName)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var archive pairingRecoveryArchive
		if err := json.Unmarshal(data, &archive); err != nil {
			t.Fatal(err)
		}
		archive.Checkpoint = strings.Repeat("0", 64)
		data, _ = json.Marshal(archive)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenPairingRecovery(dir); err == nil {
			t.Fatal("tampered archive accepted")
		}
	})
	t.Run("active-sequence-gap", func(t *testing.T) {
		dir := recoveryTestDir(t)
		recovery, err := OpenPairingRecovery(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := recovery.Begin(testRecoveryRecord(strings.Repeat("5", 32))); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, PairingOutcomeFileName)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot pairingOutcomeSnapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			t.Fatal(err)
		}
		snapshot.Records[0].Sequence = 9
		data, _ = json.Marshal(snapshot)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenPairingRecovery(dir); err == nil {
			t.Fatal("sequence gap accepted")
		}
	})
}

func TestPairingRecoveryArchiveSurvivesActiveCompactionFailure(t *testing.T) {
	dir := recoveryTestDir(t)
	recovery, err := OpenPairingRecovery(dir)
	if err != nil { t.Fatal(err) }
	id := strings.Repeat("7",32)
	if err := recovery.Begin(testRecoveryRecord(id)); err != nil { t.Fatal(err) }
	resolvePairingWithProof(t, dir, recovery, id, PairingOutcomeSuccess)
	recovery.compactionBeforeReplace = func() error { return os.ErrPermission }
	if err := recovery.AcknowledgeResolved(id); err == nil { t.Fatal("active-ledger compaction failure was ignored") }
	restarted, err := OpenPairingRecovery(dir)
	if err != nil { t.Fatal(err) }
	all, err := restarted.Records()
	if err != nil || len(all) != 1 || all[0].AttemptID != id {
		t.Fatalf("verified archive did not preserve outcome after compaction failure: %+v %v", all, err)
	}
	snapshot, err := restarted.read()
	if err != nil || len(snapshot.Records) != 0 || snapshot.ArchivedThrough != 1 {
		t.Fatalf("startup did not finish interrupted compaction: %+v %v", snapshot, err)
	}
}

func TestArchivedCredentialGenerationCannotBeReservedAgain(t *testing.T) {
	dir := recoveryTestDir(t)
	recovery, err := OpenPairingRecovery(dir)
	if err != nil { t.Fatal(err) }
	id := strings.Repeat("8",32)
	record := PairingOutcome{AttemptID:id, ActorID:testPairingActor, PeerID:testPairingPeer,
		Fingerprint:testPairingFingerprint, CredentialGeneration:77}
	if _, err := recovery.Reserve(record); err != nil { t.Fatal(err) }
	resolveAndAcknowledgePairing(t, dir, recovery, id, PairingOutcomeSuccess)
	if err := recovery.CompactResolved(); err != nil { t.Fatal(err) }
	retry := record
	retry.AttemptID = strings.Repeat("9",32)
	if _, err := recovery.Reserve(retry); err == nil { t.Fatal("archived credential generation was reused") }
}

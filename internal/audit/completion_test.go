package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/trust"
)

func completionTestEvent(id string) Event {
	return Event{
		Time: time.Now().UTC(), Type: "pairing.trust_added", Outcome: "success",
		AttemptID: id, ActorID: testPairingActor, PeerID: testPairingPeer,
		Transport: "lan",
	}
}

func completedRecoveryFixture(t *testing.T) (*PairingRecovery, *Log, string) {
	t.Helper()
	dir := recoveryTestDir(t)
	r, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	if err := r.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	if err := r.Complete(id, PairingOutcomeSuccess); err != nil {
		t.Fatal(err)
	}
	l, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	return r, l, id
}

func TestPairingCompletionProofPersistsAcrossRepeatedRotations(t *testing.T) {
	r, l, id := completedRecoveryFixture(t)
	event := completionTestEvent(id)
	if err := l.Append(event); err != nil {
		t.Fatal(err)
	}
	if err := r.AcknowledgeResolved(id); err == nil {
		t.Fatal("completion in rotating log alone permitted acknowledgment")
	}
	if err := r.ConfirmCompletion(l, id, event); err != nil {
		t.Fatal(err)
	}
	if err := r.AcknowledgeResolved(id); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 160; i++ {
		if err := l.Append(Event{
			Type: "terminal.session_closed", Outcome: "success",
			Reason: strings.Repeat("x", 250),
		}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(l.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(id)) {
		t.Fatal("fixture did not rotate completion out of active audit")
	}
	r, err = OpenPairingRecovery(filepath.Dir(l.path))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := r.Records()
	if err != nil || len(rows) != 1 || rows[0].AuditProof == nil ||
		rows[0].AuditProof.Event != event || rows[0].AcknowledgedAt == nil {
		t.Fatalf("durable audit copy lost through rotation/restart: %+v %v", rows, err)
	}
	if err := r.AcknowledgeResolved(id); err != nil {
		t.Fatalf("idempotent, nondeleting acknowledgment failed: %v", err)
	}
	rows, err = r.Records()
	if err != nil || len(rows) != 1 {
		t.Fatalf("acknowledgment deleted evidence: %+v %v", rows, err)
	}
}

func TestPairingAuditFailureNeverAcknowledged(t *testing.T) {
	r, l, id := completedRecoveryFixture(t)
	event := completionTestEvent(id)
	injected := errors.New("injected audit directory sync failure")
	l.syncDir = func(string) error { return injected }
	if err := l.Append(event); !errors.Is(err, injected) {
		t.Fatalf("audit directory sync injection ignored: %v", err)
	}
	if err := r.AcknowledgeResolved(id); err == nil {
		t.Fatal("failed audit append permitted acknowledgment")
	}
	// A visible, unconfirmed event is not proof of a successful Append.
	l.syncDir = nil
	for i := 0; i < 160; i++ {
		if err := l.Append(Event{Type: "terminal.session_closed", Outcome: "success",
			Reason: strings.Repeat("y", 250)}); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := OpenPairingRecovery(filepath.Dir(l.path))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.AcknowledgeResolved(id); err == nil {
		t.Fatal("repeated rotation/restart converted failed audit into completion")
	}
	rows, err := reopened.Records()
	if err != nil || len(rows) != 1 || rows[0].AuditProof != nil {
		t.Fatalf("failed audit evidence was lost or fabricated: %+v %v", rows, err)
	}
}

func TestPairingProofWriteAndSyncFaults(t *testing.T) {
	for _, stage := range []string{"before-replace", "after-replace", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			r, l, id := completedRecoveryFixture(t)
			event := completionTestEvent(id)
			if err := l.Append(event); err != nil {
				t.Fatal(err)
			}
			fault := errors.New("proof persistence interrupted")
			switch stage {
			case "before-replace":
				r.beforeReplace = func() error { return fault }
			case "after-replace":
				r.afterReplace = func() error { return fault }
			case "directory-sync":
				r.syncDirectory = func(string) error { return fault }
			}
			if err := r.ConfirmCompletion(l, id, event); !errors.Is(err, fault) {
				t.Fatalf("fault ignored: %v", err)
			}
			r.beforeReplace, r.afterReplace, r.syncDirectory = nil, nil, nil
			rows, err := r.Records()
			if err != nil {
				t.Fatal(err)
			}
			if stage == "before-replace" {
				if rows[0].AuditProof != nil {
					t.Fatal("proof appeared before atomic replacement")
				}
				if err := r.AcknowledgeResolved(id); err == nil {
					t.Fatal("unpersisted proof acknowledged")
				}
			} else {
				// The replacement may be visible although its directory sync
				// failed. A fresh explicit inode+directory sync can attest it.
				if err := r.AcknowledgeResolved(id); err != nil {
					t.Fatalf("visible proof could not be re-synchronized: %v", err)
				}
			}
			reopened, err := OpenPairingRecovery(filepath.Dir(l.path))
			if err != nil {
				t.Fatal(err)
			}
			rows, err = reopened.Records()
			if err != nil || len(rows) != 1 {
				t.Fatalf("proof record lost after restart: %+v %v", rows, err)
			}
		})
	}
}

func TestPairingAuditProofRejectsLegacyAndFabricatedMetadata(t *testing.T) {
	r, l, id := completedRecoveryFixture(t)
	if err := r.AcknowledgeResolved(id); err == nil {
		t.Fatal("legacy record without audit proof acknowledged")
	}
	reopened, err := OpenPairingRecovery(filepath.Dir(l.path))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.AcknowledgeResolved(id); err == nil {
		t.Fatal("legacy record implicitly upgraded on restart")
	}
	fake := completionTestEvent(id)
	fake.PeerID = "wd_cccccccccccccccc"
	if err := r.ConfirmCompletion(l, id, fake); err == nil {
		t.Fatal("fabricated event passed independent audit verification")
	}
	fake.PeerID = testPairingPeer
	if err := r.ConfirmCompletion(l, id, fake); err == nil {
		t.Fatal("nonexistent completion audit accepted")
	}
	payload, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot pairingOutcomeSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Records[0].AcknowledgedAt = new(time.Time)
	bad, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPairingRecovery(filepath.Dir(l.path)); err == nil {
		t.Fatal("malformed acknowledged legacy proof accepted")
	}
}

func TestPairingPrivilegedReconciliationAndNoSilentDeletion(t *testing.T) {
	r, l, id := completedRecoveryFixture(t)
	r.operatorCheck = func() error { return errors.New("not authorized") }
	if err := r.ReconcilePrivileged(l, id); err == nil {
		t.Fatal("unprivileged operator reconciled")
	}
	trustPath := filepath.Join(filepath.Dir(l.path), "trusted-clients.json")
	store, err := trust.Open(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	r.operatorCheck = func() error { return nil } // test-only elevated authorization seam
	if err := r.ReconcilePrivileged(l, id); err == nil {
		t.Fatal("authorization without authoritative matching trust reconciled")
	}
	if err := store.PutPairing(trust.Peer{
		ID: testPairingPeer, Fingerprint: testPairingFingerprint,
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.ReconcilePrivileged(l, id); err != nil {
		t.Fatal(err)
	}
	if err := r.AcknowledgeResolved(id); err != nil {
		t.Fatal(err)
	}
	rows, err := r.Records()
	if err != nil || len(rows) != 1 || rows[0].AuditProof == nil ||
		rows[0].AuditProof.Kind != "reconciliation" || rows[0].AcknowledgedAt == nil {
		t.Fatalf("authorized audited reconciliation did not survive: %+v %v", rows, err)
	}
	for i := 0; i < 160; i++ {
		if err := l.Append(Event{Type: "terminal.session_closed", Outcome: "success",
			Reason: strings.Repeat("q", 250)}); err != nil {
			t.Fatal(err)
		}
	}
	r, err = OpenPairingRecovery(filepath.Dir(l.path))
	if err != nil {
		t.Fatal(err)
	}
	rows, err = r.Records()
	if err != nil || len(rows) != 1 || rows[0].AuditProof == nil {
		t.Fatalf("reconciled proof disappeared after rotations: %+v %v", rows, err)
	}
}

func TestPairingRecoveryProofCapacityRemainsBoundedAfterAcknowledgment(t *testing.T) {
	r, l, id := completedRecoveryFixture(t)
	event := completionTestEvent(id)
	if err := l.Append(event); err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmCompletion(l, id, event); err != nil {
		t.Fatal(err)
	}
	if err := r.AcknowledgeResolved(id); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxPairingOutcomes; i++ {
		if err := r.Begin(testRecoveryRecord(fmt.Sprintf("%032x", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Begin(testRecoveryRecord(strings.Repeat("f", 32))); err == nil {
		t.Fatal("acknowledgment silently evicted the durable audit record")
	}
	rows, err := r.Records()
	if err != nil || len(rows) != maxPairingOutcomes {
		t.Fatalf("capacity did not retain all evidence: %d %v", len(rows), err)
	}
}

func TestPairingProofProcessChild(t *testing.T) {
	if os.Getenv("WEDECENT_PROOF_CHILD") != "1" {
		return
	}
	dir := os.Getenv("WEDECENT_PROOF_DIR")
	r, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal([]byte(os.Getenv("WEDECENT_PROOF_EVENT")), &event); err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmCompletion(l, event.AttemptID, event); err != nil {
		t.Fatal(err)
	}
}

func TestPairingProofConcurrentChildCompletionAndAcknowledgment(t *testing.T) {
	r, l, id := completedRecoveryFixture(t)
	event := completionTestEvent(id)
	if err := l.Append(event); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestPairingProofProcessChild$")
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	child.Env = append(os.Environ(), "WEDECENT_PROOF_CHILD=1",
		"WEDECENT_PROOF_DIR="+filepath.Dir(l.path), "WEDECENT_PROOF_EVENT="+string(payload))
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	failure := make(chan error, 1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(10 * time.Second)
		for {
			err := r.AcknowledgeResolved(id)
			if err == nil {
				failure <- nil
				return
			}
			if time.Now().After(deadline) {
				failure <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	childErr := child.Wait()
	wg.Wait()
	if childErr != nil {
		t.Fatalf("cross-process completion failed: %v %s", childErr, output.String())
	}
	if err := <-failure; err != nil {
		t.Fatal(err)
	}
	rows, err := r.Records()
	if err != nil || len(rows) != 1 || rows[0].AuditProof == nil ||
		rows[0].AcknowledgedAt == nil {
		t.Fatalf("concurrent operator ack lost completion: %+v %v", rows, err)
	}
}

func TestPairingProofChildKilledPostReplace(t *testing.T) {
	if os.Getenv("WEDECENT_PROOF_KILL_CHILD") != "1" {
		return
	}
	dir := os.Getenv("WEDECENT_PROOF_DIR")
	r, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal([]byte(os.Getenv("WEDECENT_PROOF_EVENT")), &event); err != nil {
		t.Fatal(err)
	}
	r.afterReplace = func() error {
		ready := os.Getenv("WEDECENT_PROOF_READY")
		if err := os.WriteFile(ready, []byte("post-replacement"), 0o600); err != nil {
			return err
		}
		for {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if err := r.ConfirmCompletion(l, event.AttemptID, event); err != nil {
		t.Fatal(err)
	}
	t.Fatal("unreachable: child did not block after replacement")
}

func TestPairingProofPostReplaceKilledProcessReopensWithoutEvidenceLoss(t *testing.T) {
	_, l, id := completedRecoveryFixture(t)
	event := completionTestEvent(id)
	if err := l.Append(event); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(filepath.Dir(l.path), "proof-kill-ready")
	child := exec.Command(exe, "-test.run=^TestPairingProofChildKilledPostReplace$")
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	child.Env = append(os.Environ(),
		"WEDECENT_PROOF_KILL_CHILD=1",
		"WEDECENT_PROOF_DIR="+filepath.Dir(l.path),
		"WEDECENT_PROOF_EVENT="+string(payload),
		"WEDECENT_PROOF_READY="+ready)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child did not reach post-replacement injection: %s", output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	reopened, err := OpenPairingRecovery(filepath.Dir(l.path))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.AcknowledgeResolved(id); err != nil {
		t.Fatalf("visible post-replace proof could not be explicitly re-synchronized: %v", err)
	}
	rows, err := reopened.Records()
	if err != nil || len(rows) != 1 || rows[0].AuditProof == nil ||
		rows[0].AcknowledgedAt == nil || rows[0].AuditProof.Event != event {
		t.Fatalf("process death lost or corrupted pairing proof: %+v %v", rows, err)
	}
	// Process kill is NOT physical power-loss persistence evidence.
}

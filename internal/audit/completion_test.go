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

func TestPairingCompletionRejectsForeignAuditLogSource(t *testing.T) {
	r, l, id := completedRecoveryFixture(t)
	event := completionTestEvent(id)
	other := recoveryTestDir(t)
	foreign, err := open(filepath.Join(other, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	if err := foreign.Append(event); err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmCompletion(foreign, id, event); err == nil {
		t.Fatal("foreign audit log supplied proof for another state root")
	}
	if err := r.AcknowledgeResolved(id); err == nil {
		t.Fatal("foreign completion proof permitted acknowledgment")
	}
	if err := l.Append(event); err != nil {
		t.Fatal(err)
	}
	if err := r.ConfirmCompletion(l, id, event); err != nil {
		t.Fatalf("valid matching audit log was rejected: %v", err)
	}
}

func TestPairingCompletionJSONLProductionBoundaries(t *testing.T) {
	record := func(payload []byte) []byte {
		line := append([]byte(nil), payload...)
		return append(line, '\n')
	}
	join := func(records ...[]byte) []byte {
		var data []byte
		for _, item := range records {
			data = append(data, item...)
		}
		return data
	}
	paddedRecord := func(payload []byte, totalBytes int) []byte {
		if totalBytes < len(payload)+1 {
			t.Fatalf("record size %d cannot contain %d-byte JSON plus newline", totalBytes, len(payload))
		}
		line := append([]byte(nil), payload...)
		line = append(line, bytes.Repeat([]byte{' '}, totalBytes-len(payload)-1)...)
		return append(line, '\n')
	}

	type recordBuilder func(target, other []byte, maxBytes int64) []byte
	tests := []struct {
		name       string
		active     recordBuilder
		archive    recordBuilder
		wantErr    bool
		leakMarker string
	}{
		{
			name: "valid JSONL with records before and after target",
			active: func(target, other []byte, _ int64) []byte {
				return join(record(other), record(target), record(other))
			},
		},
		{
			name:    "empty active log with valid archive",
			active:  func(_, _ []byte, _ int64) []byte { return nil },
			archive: func(target, _ []byte, _ int64) []byte { return record(target) },
		},
		{
			name:    "empty active log without archive evidence",
			active:  func(_, _ []byte, _ int64) []byte { return nil },
			wantErr: true,
		},
		{
			name: "leading blank record",
			active: func(target, _ []byte, _ int64) []byte {
				return join([]byte{'\n'}, record(target))
			},
			wantErr: true,
		},
		{
			name: "interior blank record",
			active: func(target, other []byte, _ int64) []byte {
				return join(record(other), []byte{'\n'}, record(target))
			},
			wantErr: true,
		},
		{
			name: "additional trailing blank record",
			active: func(target, _ []byte, _ int64) []byte {
				return join(record(target), []byte{'\n'})
			},
			wantErr: true,
		},
		{
			name: "multiple additional trailing blank records",
			active: func(target, _ []byte, _ int64) []byte {
				return join(record(target), []byte("\n\n"))
			},
			wantErr: true,
		},
		{
			name:    "blank-only log",
			active:  func(_, _ []byte, _ int64) []byte { return []byte{'\n'} },
			wantErr: true,
		},
		{
			name: "JSON null record",
			active: func(target, _ []byte, _ int64) []byte {
				return join(record(target), []byte("null\n"))
			},
			wantErr: true,
		},
		{
			name: "empty object record",
			active: func(target, _ []byte, _ int64) []byte {
				return join(record(target), []byte("{}\n"))
			},
			wantErr: true,
		},
		{
			name: "missing timestamp",
			active: func(target, _ []byte, _ int64) []byte {
				missing := []byte("{\"type\":\"pairing.trust_added\",\"outcome\":\"success\"}\n")
				return join(record(target), missing)
			},
			wantErr: true,
		},
		{
			name: "missing event type",
			active: func(target, _ []byte, _ int64) []byte {
				missing := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"outcome\":\"success\"}\n")
				return join(record(target), missing)
			},
			wantErr: true,
		},
		{
			name: "missing outcome",
			active: func(target, _ []byte, _ int64) []byte {
				missing := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"type\":\"pairing.trust_added\"}\n")
				return join(record(target), missing)
			},
			wantErr: true,
		},
		{
			name: "zero timestamp",
			active: func(target, _ []byte, _ int64) []byte {
				zero := []byte("{\"time\":\"0001-01-01T00:00:00Z\",\"type\":\"pairing.trust_added\",\"outcome\":\"success\"}\n")
				return join(record(target), zero)
			},
			wantErr: true,
		},
		{
			name: "unknown Event field rejected by strict v1 schema",
			active: func(target, other []byte, _ int64) []byte {
				unknown := append([]byte(nil), other[:len(other)-1]...)
				unknown = append(unknown, []byte(",\"future_field\":true}\n")...)
				return join(record(target), unknown)
			},
			wantErr: true,
		},
		{
			name: "case-folded schema alias rejected",
			active: func(target, _ []byte, _ int64) []byte {
				alias := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"Type\":\"pairing.trust_added\",\"outcome\":\"success\"}\n")
				return join(record(target), alias)
			},
			wantErr: true,
		},
		{
			name: "duplicate JSON object key rejected",
			active: func(target, other []byte, _ int64) []byte {
				duplicate := []byte(fmt.Sprintf(
					"{\"time\":%q,\"type\":\"pairing.trust_added\",\"type\":\"pairing.trust_added\",\"outcome\":\"success\"}\n",
					completionTestEvent(strings.Repeat("b", 32)).Time.Format(time.RFC3339Nano),
				))
				_ = other
				return join(record(target), duplicate)
			},
			wantErr: true,
		},
		{
			name: "escaped duplicate JSON object key rejected",
			active: func(target, _ []byte, _ int64) []byte {
				duplicate := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"type\":\"pairing.trust_added\",\"\\u0074ype\":\"pairing.trust_added\",\"outcome\":\"success\"}\n")
				return join(record(target), duplicate)
			},
			wantErr: true,
		},
		{
			name: "null optional field rejected",
			active: func(target, _ []byte, _ int64) []byte {
				nullField := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"type\":\"pairing.trust_added\",\"outcome\":\"success\",\"actor_id\":null}\n")
				return join(record(target), nullField)
			},
			wantErr: true,
		},
		{
			name: "malformed complete JSON before target",
			active: func(target, _ []byte, _ int64) []byte {
				return join([]byte("{not-json}\n"), record(target))
			},
			wantErr: true,
		},
		{
			name: "malformed complete JSON after target",
			active: func(target, _ []byte, _ int64) []byte {
				return join(record(target), []byte("{not-json}\n"))
			},
			wantErr: true,
		},
		{
			name: "incomplete trailing fragment",
			active: func(target, _ []byte, _ int64) []byte {
				return join(record(target), []byte("{\"type\":"))
			},
			wantErr: true,
		},
		{
			name: "malformed record followed by incomplete fragment",
			active: func(target, _ []byte, _ int64) []byte {
				return join(record(target), []byte("{not-json}\n"), []byte("{\"type\":"))
			},
			wantErr: true,
		},
		{
			name: "unterminated final JSON record",
			active: func(target, other []byte, _ int64) []byte {
				return join(record(target), other)
			},
			wantErr: true,
		},
		{
			name:    "malformed active log does not fall back to valid archive",
			active:  func(_, _ []byte, _ int64) []byte { return []byte("{broken}\n") },
			archive: func(target, _ []byte, _ int64) []byte { return record(target) },
			wantErr: true,
		},
		{
			name:    "malformed archive is checked after active target",
			active:  func(target, _ []byte, _ int64) []byte { return record(target) },
			archive: func(_, _ []byte, _ int64) []byte { return []byte("{broken}\n") },
			wantErr: true,
		},
		{
			name: "duplicate target events in active log",
			active: func(target, _ []byte, _ int64) []byte {
				return join(record(target), record(target))
			},
			wantErr: true,
		},
		{
			name:    "duplicate target across active and archive",
			active:  func(target, _ []byte, _ int64) []byte { return record(target) },
			archive: func(target, _ []byte, _ int64) []byte { return record(target) },
			wantErr: true,
		},
		{
			name: "duplicate semantic target with alternate JSON formatting",
			active: func(target, _ []byte, _ int64) []byte {
				var parsed Event
				if err := json.Unmarshal(target, &parsed); err != nil {
					t.Fatal(err)
				}
				alternate := bytes.Replace(target, []byte(",\"type\":"), []byte(", \"type\" : "), 1)
				if bytes.Equal(alternate, target) {
					t.Fatal("test did not produce alternate JSON formatting")
				}
				return join(record(target), record(alternate))
			},
			wantErr: true,
		},
		{
			name: "equivalent instant with alternate timezone offset",
			active: func(target, _ []byte, _ int64) []byte {
				var parsed Event
				if err := json.Unmarshal(target, &parsed); err != nil {
					t.Fatal(err)
				}
				parsed.Time = parsed.Time.In(time.FixedZone("UTC-07", -7*60*60))
				alternate, err := json.Marshal(parsed)
				if err != nil {
					t.Fatal(err)
				}
				return record(alternate)
			},
		},
		{
			name: "duplicate completion across active and archive with equivalent offset timestamps",
			active: func(target, _ []byte, _ int64) []byte {
				return record(target)
			},
			archive: func(target, _ []byte, _ int64) []byte {
				var parsed Event
				if err := json.Unmarshal(target, &parsed); err != nil {
					t.Fatal(err)
				}
				parsed.Time = parsed.Time.In(time.FixedZone("UTC+05:30", 5*60*60+30*60))
				alternate, err := json.Marshal(parsed)
				if err != nil {
					t.Fatal(err)
				}
				return record(alternate)
			},
			wantErr: true,
		},
		{
			name: "invalid raw UTF-8 in string value",
			active: func(target, _ []byte, _ int64) []byte {
				bad := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"type\":\"pairing.trust_added\",\"outcome\":\"success\",\"reason\":\"sensitive-audit-secret")
				bad = append(bad, 0xff)
				bad = append(bad, []byte("\"}\n")...)
				return join(record(target), bad)
			},
			wantErr:    true,
			leakMarker: "sensitive-audit-secret",
		},
		{
			name: "invalid raw UTF-8 in object key",
			active: func(target, _ []byte, _ int64) []byte {
				bad := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"type\":\"pairing.trust_added\",\"outcome\":\"success\",\"sensitive")
				bad = append(bad, 0xff)
				bad = append(bad, []byte("\":\"sensitive-key-secret\"}\n")...)
				return join(record(target), bad)
			},
			wantErr:    true,
			leakMarker: "sensitive-key-secret",
		},
		{
			name: "unpaired high surrogate in string value",
			active: func(target, _ []byte, _ int64) []byte {
				bad := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"type\":\"pairing.trust_added\",\"outcome\":\"success\",\"reason\":\"\\uD800\"}\n")
				return join(record(target), bad)
			},
			wantErr: true,
		},
		{
			name: "unpaired low surrogate in string value",
			active: func(target, _ []byte, _ int64) []byte {
				bad := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"type\":\"pairing.trust_added\",\"outcome\":\"success\",\"reason\":\"\\uDC00\"}\n")
				return join(record(target), bad)
			},
			wantErr: true,
		},
		{
			name: "unpaired high surrogate in object key",
			active: func(target, _ []byte, _ int64) []byte {
				bad := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"type\":\"pairing.trust_added\",\"outcome\":\"success\",\"\\uD800\":\"secret\"}\n")
				return join(record(target), bad)
			},
			wantErr: true,
		},
		{
			name: "unpaired low surrogate in object key",
			active: func(target, _ []byte, _ int64) []byte {
				bad := []byte("{\"time\":\"2026-11-22T00:00:00Z\",\"type\":\"pairing.trust_added\",\"outcome\":\"success\",\"\\uDC00\":\"secret\"}\n")
				return join(record(target), bad)
			},
			wantErr: true,
		},
		{
			name: "valid escaped surrogate pair in string value",
			active: func(target, other []byte, _ int64) []byte {
				valid := bytes.Replace(other, []byte("\"outcome\":\"success\""), []byte("\"outcome\":\"success\",\"reason\":\"\\uD83D\\uDE00\""), 1)
				return join(record(target), record(valid))
			},
		},
		{
			name: "valid literal U+FFFD in string value",
			active: func(target, other []byte, _ int64) []byte {
				valid := bytes.Replace(other, []byte("\"outcome\":\"success\""), []byte("\"outcome\":\"success\",\"reason\":\"�\""), 1)
				return join(record(target), record(valid))
			},
		},
		{
			name: "event record exactly at size limit including newline",
			active: func(target, other []byte, _ int64) []byte {
				return join(paddedRecord(other, maxEventSize), record(target))
			},
		},
		{
			name: "event record one byte over size limit",
			active: func(target, other []byte, _ int64) []byte {
				return join(paddedRecord(other, maxEventSize+1), record(target))
			},
			wantErr: true,
		},
		{
			name: "file exactly at size limit",
			active: func(target, other []byte, maxBytes int64) []byte {
				targetRecord := record(target)
				remaining := int(maxBytes) - len(targetRecord)
				first := remaining / 2
				second := remaining - first
				return join(targetRecord, paddedRecord(other, first), paddedRecord(other, second))
			},
		},
		{
			name: "file one byte over size limit",
			active: func(target, other []byte, maxBytes int64) []byte {
				targetRecord := record(target)
				remaining := int(maxBytes) + 1 - len(targetRecord)
				first := remaining / 2
				second := remaining - first
				return join(targetRecord, paddedRecord(other, first), paddedRecord(other, second))
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recovery, log, id := completedRecoveryFixture(t)
			event := completionTestEvent(id)
			target, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			otherEvent := completionTestEvent(strings.Repeat("b", 32))
			other, err := json.Marshal(otherEvent)
			if err != nil {
				t.Fatal(err)
			}

			var active []byte
			if test.active != nil {
				active = test.active(target, other, log.maxBytes)
			}
			if err := os.WriteFile(log.path, active, 0o600); err != nil {
				t.Fatal(err)
			}
			if test.archive != nil {
				archivePath := filepath.Join(filepath.Dir(log.path), archiveFileName)
				archive := test.archive(target, other, log.maxBytes)
				if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			verifyErr := log.VerifyDurableEvent(event)
			if test.wantErr && verifyErr == nil {
				t.Fatal("invalid audit JSONL passed Log.VerifyDurableEvent")
			}
			if !test.wantErr && verifyErr != nil {
				t.Fatalf("valid audit JSONL failed Log.VerifyDurableEvent: %v", verifyErr)
			}
			confirmErr := recovery.ConfirmCompletion(log, id, event)
			if test.wantErr && confirmErr == nil {
				t.Fatal("invalid audit JSONL produced a completion proof")
			}
			if !test.wantErr && confirmErr != nil {
				t.Fatalf("valid audit JSONL failed PairingRecovery.ConfirmCompletion: %v", confirmErr)
			}
			if test.leakMarker != "" {
				for _, returnedErr := range []error{verifyErr, confirmErr} {
					if returnedErr != nil && strings.Contains(returnedErr.Error(), test.leakMarker) {
						t.Fatalf("externally returned parsing error disclosed sensitive audit content: %v", returnedErr)
					}
				}
			}

			reopened, err := OpenPairingRecovery(filepath.Dir(log.path))
			if err != nil {
				t.Fatal(err)
			}
			records, err := reopened.Records()
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 {
				t.Fatalf("recovery records = %d, want 1", len(records))
			}
			if test.wantErr {
				if records[0].AuditProof != nil {
					t.Fatal("rejected audit JSONL persisted a durable AuditProof")
				}
				if err := reopened.AcknowledgeResolved(id); err == nil {
					t.Fatal("rejected audit JSONL permitted acknowledgment after reopening")
				}
				return
			}
			if records[0].AuditProof == nil || records[0].AuditProof.Event != event {
				t.Fatal("valid audit JSONL did not persist its durable AuditProof")
			}
			if err := reopened.AcknowledgeResolved(id); err != nil {
				t.Fatalf("valid durable completion could not be acknowledged: %v", err)
			}
		})
	}
}

func TestPairingCompletionCanonicalizesNonUTCTimestamps(t *testing.T) {
	recovery, log, id := completedRecoveryFixture(t)
	event := completionTestEvent(id)
	event.Time = time.Date(2026, 11, 22, 12, 34, 56, 123456789, time.FixedZone("UTC+05:30", 5*60*60+30*60))

	if err := log.Append(event); err != nil {
		t.Fatalf("Append rejected non-UTC event: %v", err)
	}
	if err := log.VerifyDurableEvent(event); err != nil {
		t.Fatalf("VerifyDurableEvent did not canonicalize the original non-UTC instant: %v", err)
	}
	if err := recovery.ConfirmCompletion(log, id, event); err != nil {
		t.Fatalf("ConfirmCompletion did not canonicalize the original non-UTC instant: %v", err)
	}

	reopened, err := OpenPairingRecovery(filepath.Dir(log.path))
	if err != nil {
		t.Fatal(err)
	}
	records, err := reopened.Records()
	if err != nil || len(records) != 1 || records[0].AuditProof == nil {
		t.Fatalf("canonical completion proof did not survive reopening: %+v %v", records, err)
	}
	expected := event
	expected.Time = expected.Time.UTC()
	if records[0].AuditProof.Event != expected {
		t.Fatalf("persisted completion event was not UTC-canonical: got=%+v want=%+v", records[0].AuditProof.Event, expected)
	}
	if err := reopened.AcknowledgeResolved(id); err != nil {
		t.Fatalf("canonical non-UTC completion could not be acknowledged after reopening: %v", err)
	}
}

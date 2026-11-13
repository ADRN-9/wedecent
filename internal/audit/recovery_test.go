package audit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPairingActor = "wd_aaaaaaaaaaaaaaaa"
const testPairingPeer = "wd_bbbbbbbbbbbbbbbb"
const testPairingFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func recoveryTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	secureRecoveryTestDir(t, dir)
	return dir
}

func testRecoveryRecord(id string) PairingOutcome {
	return PairingOutcome{AttemptID: id, ActorID: testPairingActor, PeerID: testPairingPeer, Fingerprint: testPairingFingerprint}
}

func TestPairingRecoverySurvivesRepeatedAuditRotationsAndRestart(t *testing.T) {
	dir := recoveryTestDir(t)
	recovery, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	if err := recovery.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	log, err := open(filepath.Join(dir, FileName), maxEventSize+256)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 150; i++ {
		if err := log.Append(Event{Type: "terminal.session_closed", Outcome: "success", Reason: strings.Repeat("x", 260)}); err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	records, err := restarted.Records()
	if err != nil || len(records) != 1 || records[0].AttemptID != id || records[0].Outcome != PairingOutcomePending {
		t.Fatalf("pending pairing lost after rotations and restart: %+v, %v", records, err)
	}
	if err := restarted.AcknowledgeResolved(id); err == nil {
		t.Fatal("operator action silently erased an unresolved pairing")
	}
	if err := restarted.Complete(id, PairingOutcomeUncertain); err != nil {
		t.Fatal(err)
	}
	if err := restarted.AcknowledgeResolved(id); err == nil {
		t.Fatal("uncertain pairing was erased")
	}
}

func TestPairingRecoveryDurabilityFaultsAndReconciliationReadFailure(t *testing.T) {
	for _, stage := range []string{"before-replace", "after-replace", "directory-sync", "reconciliation-read"} {
		t.Run(stage, func(t *testing.T) {
			dir := recoveryTestDir(t)
			recovery, err := OpenPairingRecovery(dir)
			if err != nil {
				t.Fatal(err)
			}
			fault := errors.New("injected recovery fault")
			switch stage {
			case "before-replace":
				recovery.beforeReplace = func() error { return fault }
			case "after-replace":
				recovery.afterReplace = func() error { return fault }
			case "directory-sync":
				recovery.syncDirectory = func(string) error { return fault }
			case "reconciliation-read":
				recovery.beforeRead = func() error { return fault }
			}
			err = recovery.Begin(testRecoveryRecord(strings.Repeat("b", 32)))
			if !errors.Is(err, fault) {
				t.Fatalf("fault was ignored: %v", err)
			}
			restarted, err := OpenPairingRecovery(dir)
			if err != nil {
				t.Fatal(err)
			}
			records, err := restarted.Records()
			if err != nil {
				t.Fatal(err)
			}
			if stage == "before-replace" || stage == "reconciliation-read" {
				if len(records) != 0 {
					t.Fatal("failed pre-replacement write changed durable recovery state")
				}
			} else if len(records) != 1 || records[0].Outcome != PairingOutcomePending {
				t.Fatalf("failed post-replacement sync lost detectable pending record: %+v", records)
			}
		})
	}
}

func TestPairingRecoveryMalformedTruncatedSymlinkAndPermissionGuards(t *testing.T) {
	for name, content := range map[string]string{
		"truncated":     "{",
		"unknown-field": `{"version":1,"records":[],"unexpected":true}`,
		"bad-version":   `{"version":9,"records":[]}`,
		"duplicate":     `{"version":1,"records":[{"attempt_id":"00000000000000000000000000000000"}]}`,
		"trailing":      `{"version":1,"records":[]}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := recoveryTestDir(t)
			if err := os.WriteFile(filepath.Join(dir, PairingOutcomeFileName), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenPairingRecovery(dir); err == nil {
				t.Fatal("unsafe pairing outcome file accepted")
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		dir := recoveryTestDir(t)
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, PairingOutcomeFileName)); err != nil {
			t.Skipf("symlink privileges unavailable: %v", err)
		}
		if _, err := OpenPairingRecovery(dir); err == nil {
			t.Fatal("symlinked pairing outcome file accepted")
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("broad-permissions", func(t *testing.T) {
			dir := recoveryTestDir(t)
			recovery, err := OpenPairingRecovery(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := recovery.Begin(testRecoveryRecord(strings.Repeat("c", 32))); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(dir, PairingOutcomeFileName), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenPairingRecovery(dir); err == nil {
				t.Fatal("broad permission recovery file was accepted")
			}
		})
	}
}

func TestPairingRecoveryConcurrentAttemptsAndCapacityRepair(t *testing.T) {
	dir := recoveryTestDir(t)
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			recovery, err := OpenPairingRecovery(dir)
			if err == nil {
				record := testRecoveryRecord(fmt.Sprintf("%032x", i))
				record.PeerID = "wd_" + strings.Repeat("a", 15) + string(rune('a'+i))
				err = recovery.Begin(record)
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	recovery, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	records, err := recovery.Records()
	if err != nil || len(records) != n {
		t.Fatalf("concurrent attempts lost: %d, %v", len(records), err)
	}
	for i := n; i < maxPairingOutcomes; i++ {
		if err := recovery.Begin(testRecoveryRecord(fmt.Sprintf("%032x", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := recovery.Begin(testRecoveryRecord(strings.Repeat("f", 32))); err == nil {
		t.Fatal("full recovery register silently evicted a record")
	}
	if err := recovery.AcknowledgeResolved(fmt.Sprintf("%032x", 0)); err == nil {
		t.Fatal("pending record pruned without resolution")
	}
	if err := recovery.Complete(fmt.Sprintf("%032x", 0), PairingOutcomeSuccess); err != nil {
		t.Fatal(err)
	}
	if err := recovery.AcknowledgeResolved(fmt.Sprintf("%032x", 0)); err != nil {
		t.Fatal(err)
	}
	if err := recovery.Begin(testRecoveryRecord(strings.Repeat("f", 32))); err != nil {
		t.Fatalf("explicit resolved-record repair did not free capacity: %v", err)
	}
}

func TestPairingRecoveryChildAfterBegin(t *testing.T) {
	if os.Getenv("WEDECENT_RECOVERY_CHILD") != "1" {
		return
	}
	recovery, err := OpenPairingRecovery(os.Getenv("WEDECENT_RECOVERY_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.Begin(testRecoveryRecord(strings.Repeat("d", 32))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("WEDECENT_RECOVERY_READY"), []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPairingRecoveryProcessKilledAfterDurablePending(t *testing.T) {
	dir := recoveryTestDir(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(dir, "child-ready")
	child := exec.Command(exe, "-test.run=^TestPairingRecoveryChildAfterBegin$")
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	child.Env = append(os.Environ(), "WEDECENT_RECOVERY_CHILD=1", "WEDECENT_RECOVERY_DIR="+dir, "WEDECENT_RECOVERY_READY="+ready)
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
			t.Fatalf("child did not commit pending record: %s", output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	restarted, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := restarted.Records()
	if err != nil || len(rows) != 1 || rows[0].Outcome != PairingOutcomePending {
		t.Fatalf("pending journal lost after process kill: %+v, %v", rows, err)
	}
}

func TestPairingRecoveryRemovedFileRequiresOperatorRepair(t *testing.T) {
	dir := recoveryTestDir(t)
	r, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Begin(testRecoveryRecord(strings.Repeat("e", 32))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, PairingOutcomeFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPairingRecovery(dir); err == nil {
		t.Fatal("removed pairing recovery ledger was silently recreated")
	}
	if err := r.Begin(testRecoveryRecord(strings.Repeat("f", 32))); err == nil {
		t.Fatal("open recovery handle accepted lost ledger")
	}
}

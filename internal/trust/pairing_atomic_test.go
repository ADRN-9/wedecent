package trust

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

func pairingTestStore(t *testing.T, dir string) *Store {
	t.Helper()
	preparePairingTestDir(t, dir)
	store, err := Open(filepath.Join(dir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func pairingTestPeer(id string) Peer {
	return Peer{ID: id, Name: id, Fingerprint: "SHA256:" + strings.Repeat("A", 64)}
}

func TestPairingAtomicSequentialReplayAndRotation(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	first := pairingTestPeer("wd_aaaaaaaaaaaaaaaa")
	second := pairingTestPeer("wd_bbbbbbbbbbbbbbbb")
	if err := PairClientWithSecret(dir, "invalid", store, first); !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("invalid input: %v", err)
	}
	if err := PairClientWithSecret(dir, strings.Repeat("x", 32), store, first); !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("missing secret: %v", err)
	}
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("secret size = %d", len(secret))
	}
	if err := PairClientWithSecret(dir, "different", store, first); !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("incorrect secret: %v", err)
	}
	if err := PairClientWithSecret(dir, secret, store, first); err != nil {
		t.Fatalf("first pairing: %v", err)
	}
	if err := PairClientWithSecret(dir, secret, store, second); !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("replayed secret: %v", err)
	}
	if _, ok := store.Get(first.ID); !ok {
		t.Fatal("accepted client is not persisted")
	}
	if _, ok := store.Get(second.ID); ok {
		t.Fatal("replayed client was trusted")
	}
	rotated, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := PairClientWithSecret(dir, rotated, store, second); err != nil {
		t.Fatalf("pairing after explicit rotation: %v", err)
	}
	if _, ok := store.Get(second.ID); !ok {
		t.Fatal("rotated client trust was not persisted")
	}
}

func TestPairingAtomicConcurrentDistinctClients(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 16
	start := make(chan struct{})
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		id := fmt.Sprintf("wd_%016d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- PairClientWithSecret(dir, secret, store, pairingTestPeer(id))
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	accepted, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrPairingSecretInvalid):
			rejected++
		default:
			t.Fatalf("unexpected transaction error: %v", err)
		}
	}
	if accepted != 1 || rejected != callers-1 || len(store.List()) != 1 {
		t.Fatalf("accepted=%d rejected=%d persisted=%d", accepted, rejected, len(store.List()))
	}
}

// Run the same compiled Go test executable in two independent OS processes.
// A shared start file ensures both attempt to consume one persistent secret.
func TestPairingAtomicCrossProcessConsumption(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := filepath.Join(dir, "children-start")
	type child struct {
		cmd   *exec.Cmd
		out   bytes.Buffer
		ready string
	}
	children := make([]*child, 2)
	for i := range children {
		id := fmt.Sprintf("wd_%016d", i+1)
		c := &child{
			cmd:   exec.Command(exe, "-test.run=^TestPairingAtomicChildProcess$"),
			ready: filepath.Join(dir, fmt.Sprintf("child-ready-%d", i)),
		}
		c.cmd.Env = append(os.Environ(),
			"WEDECENT_PAIRING_TEST_CHILD=1",
			"WEDECENT_PAIRING_TEST_DIR="+dir,
			"WEDECENT_PAIRING_TEST_SECRET="+secret,
			"WEDECENT_PAIRING_TEST_PEER="+id,
			"WEDECENT_PAIRING_TEST_READY="+c.ready,
			"WEDECENT_PAIRING_TEST_START="+start,
		)
		c.cmd.Stdout = &c.out
		c.cmd.Stderr = &c.out
		if err := c.cmd.Start(); err != nil {
			for j := 0; j < i; j++ {
				_ = children[j].cmd.Process.Kill()
				_ = children[j].cmd.Wait()
			}
			t.Fatal(err)
		}
		children[i] = c
	}
	deadline := time.Now().Add(10 * time.Second)
	for _, c := range children {
		for {
			if _, err := os.Stat(c.ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				for _, active := range children {
					_ = active.cmd.Process.Kill()
					_ = active.cmd.Wait()
				}
				t.Fatalf("child never became ready: %s", c.ready)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := os.WriteFile(start, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	accepted, denied := 0, 0
	for _, c := range children {
		if err := c.cmd.Wait(); err != nil {
			t.Fatalf("child failed: %v, output=%s", err, c.out.String())
		}
		switch {
		case strings.Contains(c.out.String(), "WEDECENT_CHILD_PAIR_OK"):
			accepted++
		case strings.Contains(c.out.String(), "WEDECENT_CHILD_PAIR_REPLAY"):
			denied++
		default:
			t.Fatalf("unclassified child outcome: %q", c.out.String())
		}
	}
	if accepted != 1 || denied != 1 || len(store.List()) != 1 {
		t.Fatalf("accepted=%d denied=%d trusted=%d", accepted, denied, len(store.List()))
	}
}

// A killed worker must not leave the secret reusable or the peer trusted.
// Hold the trust-store lock so the child stops after consuming the secret but
// before persistence, then kill it and restart the authorization attempt.
func TestPairingAtomicInterruptedAfterConsumption(t *testing.T) {
	dir := t.TempDir()
	pairingTestStore(t, dir)
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlockStore, err := lockStoreFile(filepath.Join(dir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if unlockStore != nil {
			unlockStore()
		}
	}()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := filepath.Join(dir, "interrupted-start")
	ready := filepath.Join(dir, "interrupted-ready")
	child := exec.Command(exe, "-test.run=^TestPairingAtomicChildProcess$")
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	child.Env = append(os.Environ(),
		"WEDECENT_PAIRING_TEST_CHILD=1",
		"WEDECENT_PAIRING_TEST_DIR="+dir,
		"WEDECENT_PAIRING_TEST_SECRET="+secret,
		"WEDECENT_PAIRING_TEST_PEER=wd_aaaaaaaaaaaaaaaa",
		"WEDECENT_PAIRING_TEST_READY="+ready,
		"WEDECENT_PAIRING_TEST_START="+start,
	)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("interrupted helper not ready: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.WriteFile(start, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(dir, pairingSecretFile)
	for {
		if _, err := readPairingHash(secretPath); errors.Is(err, ErrPairingSecretInvalid) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child did not consume secret: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	unlockStore()
	unlockStore = nil
	// Re-open after process death to prove persistent trust was not modified.
	reopened, err := Open(filepath.Join(dir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	peer := pairingTestPeer("wd_aaaaaaaaaaaaaaaa")
	if _, ok := reopened.Get(peer.ID); ok {
		t.Fatal("interrupted persistence inserted trust")
	}
	if err := PairClientWithSecret(dir, secret, reopened, peer); !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("interrupted operation left reusable secret: %v", err)
	}
}

func TestPairingAtomicChildProcess(t *testing.T) {
	if os.Getenv("WEDECENT_PAIRING_TEST_CHILD") != "1" {
		return
	}
	dir := os.Getenv("WEDECENT_PAIRING_TEST_DIR")
	store, err := Open(filepath.Join(dir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("WEDECENT_PAIRING_TEST_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv("WEDECENT_PAIRING_TEST_START")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("start gate never opened")
		}
		time.Sleep(10 * time.Millisecond)
	}
	err = PairClientWithSecret(dir, os.Getenv("WEDECENT_PAIRING_TEST_SECRET"), store,
		pairingTestPeer(os.Getenv("WEDECENT_PAIRING_TEST_PEER")))
	switch {
	case err == nil:
		fmt.Println("WEDECENT_CHILD_PAIR_OK")
	case errors.Is(err, ErrPairingSecretInvalid):
		fmt.Println("WEDECENT_CHILD_PAIR_REPLAY")
	default:
		t.Fatal(err)
	}
}

func TestPairingAtomicLockFailureDoesNotTrust(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	// A directory in place of the lock cannot be opened as a lock file.
	if err := os.Mkdir(filepath.Join(dir, pairingSecretFile+".lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	peer := pairingTestPeer("wd_aaaaaaaaaaaaaaaa")
	if _, err := RotatePairingSecret(dir); !errors.Is(err, ErrPairingStateUnsafe) {
		t.Fatalf("rotation accepted unsafe lock: %v", err)
	}
	if err := PairClientWithSecret(dir, strings.Repeat("A", 32), store, peer); !errors.Is(err, ErrPairingStateUnsafe) {
		t.Fatalf("pairing accepted unsafe lock: %v", err)
	}
	if _, ok := store.Get(peer.ID); ok {
		t.Fatal("trust added after locking failure")
	}
}

func TestPairingAtomicRejectsSymlinkedSecretAndLock(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, pairingSecretFile)
	target := filepath.Join(dir, "innocent")
	if err := os.WriteFile(target, []byte("do not change"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("creating symlinks is unsupported: %v", err)
	}
	peer := pairingTestPeer("wd_aaaaaaaaaaaaaaaa")
	if err := PairClientWithSecret(dir, secret, store, peer); !errors.Is(err, ErrPairingStateUnsafe) {
		t.Fatalf("pairing accepted symlinked secret: %v", err)
	}
	if _, err := RotatePairingSecret(dir); !errors.Is(err, ErrPairingStateUnsafe) {
		t.Fatalf("rotation replaced symlink: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "do not change" {
		t.Fatalf("symlink destination changed: %q %v", got, err)
	}
	if _, ok := store.Get(peer.ID); ok {
		t.Fatal("trust inserted despite symlink")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	lockPath := path + ".lock"
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lockPath); err != nil {
		t.Skipf("lock symlinks unsupported: %v", err)
	}
	if _, err := RotatePairingSecret(dir); !errors.Is(err, ErrPairingStateUnsafe) {
		t.Fatalf("rotation accepted symlink lock: %v", err)
	}
	got, err = os.ReadFile(target)
	if err != nil || string(got) != "do not change" {
		t.Fatalf("lock target changed: %q %v", got, err)
	}
}

func TestPairingAtomicMalformedOrPartialStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	path := filepath.Join(dir, pairingSecretFile)
	if err := os.WriteFile(path, []byte("incomplete"), 0o600); err != nil {
		t.Fatal(err)
	}
	peer := pairingTestPeer("wd_aaaaaaaaaaaaaaaa")
	if err := PairClientWithSecret(dir, strings.Repeat("A", 32), store, peer); !errors.Is(err, ErrPairingStateUnsafe) {
		t.Fatalf("malformed hash was accepted: %v", err)
	}
	if _, err := RotatePairingSecret(dir); !errors.Is(err, ErrPairingStateUnsafe) {
		t.Fatalf("malformed state overwritten: %v", err)
	}
	if _, ok := store.Get(peer.ID); ok {
		t.Fatal("trust inserted after malformed hash")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := PairClientWithSecret(dir, strings.Repeat("A", 32), store, peer); !errors.Is(err, ErrPairingStateUnsafe) {
			t.Fatalf("public-readable hash was accepted: %v", err)
		}
	}
}

func TestPairingAtomicTrustPersistenceFailureBurnsSecret(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Turn the previously absent trust-store path into an unsafe directory.
	// Store.Put must fail without reporting a successful grant of trust.
	if err := os.Mkdir(filepath.Join(dir, "trusted-clients.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	peer := pairingTestPeer("wd_aaaaaaaaaaaaaaaa")
	if err := PairClientWithSecret(dir, secret, store, peer); !errors.Is(err, ErrPairingTrustUncertain) {
		t.Fatalf("unverifiable trust persistence was not classified: %v", err)
	}
	if err := PairClientWithSecret(dir, secret, store, peer); !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("consumed secret replayed after persistence failure: %v", err)
	}
	if _, ok := store.Get(peer.ID); ok {
		t.Fatal("trust inserted after failed persistence")
	}
}

func TestPairingAtomicRotationRaceIsSerializable(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, unlock, err := lockPairing(dir)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	pairDone := make(chan error, 1)
	type rotation struct {
		secret string
		err    error
	}
	rotationDone := make(chan rotation, 1)
	go func() {
		<-start
		pairDone <- PairClientWithSecret(dir, secret, store, pairingTestPeer("wd_aaaaaaaaaaaaaaaa"))
	}()
	go func() {
		<-start
		s, e := RotatePairingSecret(dir)
		rotationDone <- rotation{s, e}
	}()
	close(start)
	unlock()
	pairErr := <-pairDone
	rotated := <-rotationDone
	if rotated.err != nil {
		t.Fatalf("racing rotation: %v", rotated.err)
	}
	if pairErr != nil && !errors.Is(pairErr, ErrPairingSecretInvalid) {
		t.Fatalf("racing pairing: %v", pairErr)
	}
	if err := PairClientWithSecret(dir, secret, store, pairingTestPeer("wd_bbbbbbbbbbbbbbbb")); !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("old secret remains valid: %v", err)
	}
	if err := PairClientWithSecret(dir, rotated.secret, store, pairingTestPeer("wd_cccccccccccccccc")); err != nil {
		t.Fatalf("new secret not usable after rotation: %v", err)
	}
	if _, ok := store.Get("wd_bbbbbbbbbbbbbbbb"); ok {
		t.Fatal("stale secret trusted a client")
	}
}

func TestPairingAtomicControlledInterleaving(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() {
		firstDone <- pairClientWithHooks(dir, secret, store, pairingTestPeer("wd_aaaaaaaaaaaaaaaa"),
			pairingHooks{beforeConsume: func() {
				close(entered)
				<-release
			}})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first consumer failed to enter locked transaction")
	}
	secondReachedLock := make(chan struct{})
	go func() {
		secondDone <- pairClientWithHooks(dir, secret, store, pairingTestPeer("wd_bbbbbbbbbbbbbbbb"),
			pairingHooks{beforeAcquire: func() { close(secondReachedLock) }})
	}()
	select {
	case <-secondReachedLock:
	case <-time.After(5 * time.Second):
		t.Fatal("second client did not reach pairing lock acquisition")
	}
	// Both consumers reached acquisition, while the first still holds the
	// cross-process lock. The second must not authorize or complete.
	select {
	case err := <-secondDone:
		t.Fatalf("second consumer completed before lock release: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first transaction: %v", err)
	}
	if err := <-secondDone; !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("second transaction: %v", err)
	}
	if n := len(store.List()); n != 1 {
		t.Fatalf("trusted identities = %d, want one", n)
	}
}

func TestPairingAtomicDurableTombstoneAndInjectedWriteFailures(t *testing.T) {
	t.Run("sync-completed-marker", func(t *testing.T) {
		dir := t.TempDir()
		store := pairingTestStore(t, dir)
		secret, err := RotatePairingSecret(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := PairClientWithSecret(dir, secret, store, pairingTestPeer("wd_aaaaaaaaaaaaaaaa")); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, pairingSecretFile))
		if err != nil || string(data) != consumedPairingHash+"\n" {
			t.Fatalf("consumed marker = %q, error=%v", data, err)
		}
		if err := PairClientWithSecret(dir, secret, store, pairingTestPeer("wd_bbbbbbbbbbbbbbbb")); !errors.Is(err, ErrPairingSecretInvalid) {
			t.Fatalf("durable marker accepted replay: %v", err)
		}
	})
	t.Run("crash-after-consumption-before-persistence", func(t *testing.T) {
		dir := t.TempDir()
		store := pairingTestStore(t, dir)
		secret, err := RotatePairingSecret(dir)
		if err != nil {
			t.Fatal(err)
		}
		err = pairClientWithHooks(dir, secret, store, pairingTestPeer("wd_aaaaaaaaaaaaaaaa"),
			pairingHooks{afterConsume: func() error { return errors.New("injected interruption") }})
		if !errors.Is(err, ErrPairingStateUnsafe) {
			t.Fatalf("interrupted transaction: %v", err)
		}
		if len(store.List()) != 0 {
			t.Fatal("interrupted transaction inserted trust")
		}
		if err := PairClientWithSecret(dir, secret, store, pairingTestPeer("wd_bbbbbbbbbbbbbbbb")); !errors.Is(err, ErrPairingSecretInvalid) {
			t.Fatalf("interrupted transaction allowed replay: %v", err)
		}
	})
	t.Run("precommit-store-failure", func(t *testing.T) {
		dir := t.TempDir()
		store := pairingTestStore(t, dir)
		secret, err := RotatePairingSecret(dir)
		if err != nil {
			t.Fatal(err)
		}
		err = pairClientWithHooks(dir, secret, store, pairingTestPeer("wd_aaaaaaaaaaaaaaaa"),
			pairingHooks{putTrust: func(Peer) error { return errors.New("injected write failure") }})
		if !errors.Is(err, ErrPairingTrustPersist) {
			t.Fatalf("precommit failure: %v", err)
		}
		if len(store.List()) != 0 {
			t.Fatal("failed write inserted trust")
		}
		if err := PairClientWithSecret(dir, secret, store, pairingTestPeer("wd_bbbbbbbbbbbbbbbb")); !errors.Is(err, ErrPairingSecretInvalid) {
			t.Fatalf("failed write allowed replay: %v", err)
		}
	})
	t.Run("postcommit-error-reconciles", func(t *testing.T) {
		dir := t.TempDir()
		store := pairingTestStore(t, dir)
		secret, err := RotatePairingSecret(dir)
		if err != nil {
			t.Fatal(err)
		}
		peer := pairingTestPeer("wd_aaaaaaaaaaaaaaaa")
		err = pairClientWithHooks(dir, secret, store, peer,
			pairingHooks{putTrust: func(p Peer) error {
				if err := store.PutPairing(p); err != nil {
					return err
				}
				return fmt.Errorf("%w: injected error after commit", errTrustStoreCommitted)
			}})
		if !IsPairingReconciled(err) {
			t.Fatalf("committed write not reconciled: %v", err)
		}
		if got, ok := store.Get(peer.ID); !ok || got.Fingerprint != peer.Fingerprint {
			t.Fatal("reconciled peer is not durable in the trust store")
		}
		if err := PairClientWithSecret(dir, secret, store, pairingTestPeer("wd_bbbbbbbbbbbbbbbb")); !errors.Is(err, ErrPairingSecretInvalid) {
			t.Fatalf("reconciled commit allowed replay: %v", err)
		}
	})
}

func TestPairingAtomicRotationCannotOvertakeCriticalSection(t *testing.T) {
	dir := t.TempDir()
	store := pairingTestStore(t, dir)
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	pairDone := make(chan error, 1)
	type rotatedResult struct {
		secret string
		err    error
	}
	rotateDone := make(chan rotatedResult, 1)
	go func() {
		pairDone <- pairClientWithHooks(dir, secret, store, pairingTestPeer("wd_aaaaaaaaaaaaaaaa"),
			pairingHooks{beforeConsume: func() {
				close(entered)
				<-release
			}})
	}()
	<-entered
	go func() {
		s, err := RotatePairingSecret(dir)
		rotateDone <- rotatedResult{secret: s, err: err}
	}()
	select {
	case got := <-rotateDone:
		t.Fatalf("rotation overtook held pairing lock: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-pairDone; err != nil {
		t.Fatal(err)
	}
	got := <-rotateDone
	if got.err != nil {
		t.Fatal(got.err)
	}
	if err := PairClientWithSecret(dir, got.secret, store, pairingTestPeer("wd_bbbbbbbbbbbbbbbb")); err != nil {
		t.Fatalf("new secret failed after ordered rotation: %v", err)
	}
}

func TestPairingTrustCommitBoundaries(t *testing.T) {
	injected := errors.New("injected trust persistence fault")
	for _, tc := range []struct {
		name           string
		configure      func(*Store)
		withHooks      func(*Store) pairingHooks
		wantErr        error
		wantVisible    bool
		wantReconciled bool
	}{
		{
			name: "before-replacement",
			configure: func(s *Store) {
				s.commitHooks.beforeReplace = func() error { return injected }
			},
			wantErr: ErrPairingTrustPersist,
		},
		{
			name: "after-replacement-before-sync",
			configure: func(s *Store) {
				s.commitHooks.afterReplace = func() error { return injected }
			},
			wantErr: ErrPairingTrustUncertain, wantVisible: true,
		},
		{
			name: "during-directory-sync",
			configure: func(s *Store) {
				s.commitHooks.syncDirectory = func(string) error { return injected }
			},
			wantErr: ErrPairingTrustUncertain, wantVisible: true,
		},
		{
			name: "after-confirmed-durable-commit",
			configure: func(s *Store) {
				s.commitHooks.afterCommit = func() error { return injected }
			},
			wantVisible: true, wantReconciled: true,
		},
		{
			name: "reconciliation-read-error",
			configure: func(s *Store) {
				s.commitHooks.afterReplace = func() error { return injected }
			},
			withHooks: func(*Store) pairingHooks {
				return pairingHooks{reconcileTrust: func(Peer) (bool, error) {
					return false, os.ErrPermission
				}}
			},
			wantErr: ErrPairingTrustUncertain, wantVisible: true,
		},
		{
			name: "unattested-error-after-actually-durable-commit",
			withHooks: func(s *Store) pairingHooks {
				return pairingHooks{putTrust: func(p Peer) error {
					if err := s.PutPairing(p); err != nil {
						return err
					}
					return injected // No trusted commit proof accompanies this error.
				}}
			},
			wantErr: ErrPairingTrustUncertain, wantVisible: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := pairingTestStore(t, dir)
			secret, err := RotatePairingSecret(dir)
			if err != nil {
				t.Fatal(err)
			}
			if tc.configure != nil {
				tc.configure(s)
			}
			hooks := pairingHooks{}
			if tc.withHooks != nil {
				hooks = tc.withHooks(s)
			}
			peer := pairingTestPeer("wd_aaaaaaaaaaaaaaaa")
			err = pairClientWithHooks(dir, secret, s, peer, hooks)
			if tc.wantReconciled {
				if !IsPairingReconciled(err) {
					t.Fatalf("confirmed commit not reconciled: %v", err)
				}
			} else if !errors.Is(err, tc.wantErr) || IsPairingReconciled(err) {
				t.Fatalf("unexpected pairing result: got %v, want %v", err, tc.wantErr)
			}
			// Reopening represents a fresh process reading disk, not a claim
			// about how the filesystem survives sudden physical power loss.
			reopened, err := Open(filepath.Join(dir, "trusted-clients.json"))
			if err != nil {
				t.Fatal(err)
			}
			_, visible := reopened.Get(peer.ID)
			if visible != tc.wantVisible {
				t.Fatalf("snapshot visible=%v, want %v", visible, tc.wantVisible)
			}
			if err := PairClientWithSecret(dir, secret, reopened,
				pairingTestPeer("wd_bbbbbbbbbbbbbbbb")); !errors.Is(err, ErrPairingSecretInvalid) {
				t.Fatalf("consumed secret accepted after restart: %v", err)
			}
		})
	}
}

// The child is killed after atomic replacement but before the Go pairing
// directory-sync barrier. This is process-crash evidence, not power-loss proof.
func TestPairingPostReplaceCrashChild(t *testing.T) {
	if os.Getenv("WEDECENT_POST_REPLACE_CHILD") != "1" {
		return
	}
	dir := os.Getenv("WEDECENT_POST_REPLACE_DIR")
	s, err := Open(filepath.Join(dir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.commitHooks.afterReplace = func() error {
		if err := os.WriteFile(os.Getenv("WEDECENT_POST_REPLACE_READY"), []byte("replaced"), 0o600); err != nil {
			return err
		}
		for {
			time.Sleep(50 * time.Millisecond)
		}
	}
	t.Fatal(PairClientWithSecret(dir, os.Getenv("WEDECENT_POST_REPLACE_SECRET"),
		s, pairingTestPeer("wd_aaaaaaaaaaaaaaaa")))
}

func TestPairingPostReplaceKilledProcessCannotReplay(t *testing.T) {
	dir := t.TempDir()
	pairingTestStore(t, dir)
	secret, err := RotatePairingSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(dir, "post-replace-ready")
	child := exec.Command(exe, "-test.run=^TestPairingPostReplaceCrashChild$")
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	child.Env = append(os.Environ(),
		"WEDECENT_POST_REPLACE_CHILD=1",
		"WEDECENT_POST_REPLACE_DIR="+dir,
		"WEDECENT_POST_REPLACE_READY="+ready,
		"WEDECENT_POST_REPLACE_SECRET="+secret,
	)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child did not reach post-replace barrier: %s", output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	reopened, err := Open(filepath.Join(dir, "trusted-clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, found := reopened.Get("wd_aaaaaaaaaaaaaaaa"); !found {
		t.Fatal("replaced snapshot was not visible after the child died")
	}
	if err := PairClientWithSecret(dir, secret, reopened,
		pairingTestPeer("wd_bbbbbbbbbbbbbbbb")); !errors.Is(err, ErrPairingSecretInvalid) {
		t.Fatalf("restarting after post-replacement crash reused secret: %v", err)
	}
}

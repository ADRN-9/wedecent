package trust

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStoreReloadsExternalRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	if err := writer.Put(peer); err != nil {
		t.Fatal(err)
	}

	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reader.FindByFingerprint(peer.Fingerprint); !ok {
		t.Fatal("peer missing before revocation")
	}
	if _, err := Revoke(path, peer.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := reader.FindByFingerprint(peer.Fingerprint); ok {
		t.Fatal("separately opened store retained revoked peer")
	}
}

func TestRevokeRemovesOnlyExactPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-devices.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "first", Fingerprint: "fp-a"}
	second := Peer{ID: "wd_bbbbbbbbbbbbbbbb", Name: "second", Fingerprint: "fp-b"}
	if err := store.Put(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(second); err != nil {
		t.Fatal(err)
	}

	removed, err := Revoke(path, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if removed.ID != first.ID || removed.Fingerprint != first.Fingerprint {
		t.Fatalf("unexpected removed peer: %#v", removed)
	}
	if _, ok := store.Get(first.ID); ok {
		t.Fatal("revoked peer still present")
	}
	if got, ok := store.Get(second.ID); !ok || got.Fingerprint != second.Fingerprint {
		t.Fatal("unrelated peer was modified")
	}

	if _, err := Revoke(path, first.ID); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("second revoke error = %v, want ErrPeerNotFound", err)
	}
}

func TestRevokeRejectsInvalidIDBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trusted-devices.json")
	if _, err := Revoke(path, "../trusted-clients.json"); err == nil {
		t.Fatal("invalid ID unexpectedly accepted")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trust store was mutated for invalid ID: %v", err)
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock file was created for invalid ID: %v", err)
	}
}

func TestConcurrentStoresPreserveBothPuts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	firstStore, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peers := []Peer{
		{ID: "wd_aaaaaaaaaaaaaaaa", Name: "first", Fingerprint: "fp-a"},
		{ID: "wd_bbbbbbbbbbbbbbbb", Name: "second", Fingerprint: "fp-b"},
	}
	stores := []*Store{firstStore, secondStore}

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := range stores {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs <- stores[i].Put(peers[i])
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	final, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if got, ok := final.Get(peer.ID); !ok || got.Fingerprint != peer.Fingerprint {
			t.Fatalf("missing concurrent peer %s", peer.ID)
		}
	}
}

func TestReloadFailureFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.FindByFingerprint(peer.Fingerprint); ok {
		t.Fatal("corrupt refreshed trust store authorized a peer")
	}
}

func TestWithTrustedPeerAdmissionWinsBeforeRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	admitted := make(chan error, 1)
	go func() {
		admitted <- store.WithTrustedPeer(peer.ID, peer.Fingerprint, func(got Peer) error {
			if got.ID != peer.ID || !validPeerGeneration(got.Generation) {
				return errors.New("admitted peer identity or generation is invalid")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	revocationStarted := make(chan struct{})
	revoked := make(chan error, 1)
	go func() {
		close(revocationStarted)
		_, err := Revoke(path, peer.ID)
		revoked <- err
	}()
	<-revocationStarted
	close(release)

	if err := <-admitted; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.Lookup(peer.ID); err != nil || ok {
		t.Fatalf("revoked peer lookup = (ok %v, err %v)", ok, err)
	}
}

func TestWithTrustedPeerRevocationWinsBeforeAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
	if _, err := Revoke(path, peer.ID); err != nil {
		t.Fatal(err)
	}

	callbackRan := false
	err = store.WithTrustedPeer(peer.ID, peer.Fingerprint, func(Peer) error {
		callbackRan = true
		return nil
	})
	if !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("admission after revocation error = %v, want ErrPeerNotFound", err)
	}
	if callbackRan {
		t.Fatal("admission callback ran after revocation won")
	}
}

func TestLookupReturnsTrustStoreReadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.Lookup(peer.ID); err == nil || ok {
		t.Fatalf("malformed trust store lookup = (ok %v, err %v), want read error", ok, err)
	}
}

func TestConcurrentRevocationsOnlyOneSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := Revoke(path, peer.ID)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes, missing := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrPeerNotFound):
			missing++
		default:
			t.Fatalf("unexpected concurrent revoke error: %v", err)
		}
	}
	if successes != 1 || missing != 1 {
		t.Fatalf("concurrent revoke outcomes = success %d, missing %d; want one each", successes, missing)
	}
}

func TestPeerGenerationChangesAfterRevocationAndRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
	before, ok := store.Get(peer.ID)
	if !ok || before.Generation == "" {
		t.Fatalf("initial peer generation = %q, trusted %v", before.Generation, ok)
	}
	if _, err := Revoke(path, peer.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
	after, ok := store.Get(peer.ID)
	if !ok || after.Generation == "" || after.Generation == before.Generation {
		t.Fatalf("repaired peer generation = %q, want a new generation after %q", after.Generation, before.Generation)
	}
}

func TestPeerGenerationSurvivesMetadataUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Get(peer.ID)
	peer.Name = "renamed client"
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
	after, _ := store.Get(peer.ID)
	if after.Generation == "" || after.Generation != before.Generation {
		t.Fatalf("metadata update changed trust generation: before %q after %q", before.Generation, after.Generation)
	}
}

func TestOpenMigratesLegacyPeersWithNoGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-clients.json")
	legacy := `{"peers":{"wd_aaaaaaaaaaaaaaaa":{"id":"wd_aaaaaaaaaaaaaaaa","name":"client","fingerprint":"fp-a","trusted_at":"2026-01-01T00:00:00Z"}}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := store.Get("wd_aaaaaaaaaaaaaaaa")
	if !ok || peer.Generation == "" {
		t.Fatalf("legacy peer generation = %q, trusted %v", peer.Generation, ok)
	}
}

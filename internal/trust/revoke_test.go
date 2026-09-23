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

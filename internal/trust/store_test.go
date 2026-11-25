package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreCanReplaceExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-devices.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "one", Fingerprint: "SHA256:ONE", Endpoint: "tcp://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(Peer{ID: "wd_bbbbbbbbbbbbbbbb", Name: "two", Fingerprint: "SHA256:TWO", Endpoint: "tcp://127.0.0.1:2"}); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Get("wd_aaaaaaaaaaaaaaaa"); !ok {
		t.Fatal("first peer missing after replacement")
	}
	if _, ok := reopened.Get("wd_bbbbbbbbbbbbbbbb"); !ok {
		t.Fatal("second peer missing after replacement")
	}
}

func TestOpenRejectsSymlink(t *testing.T) {
	if testing.Short() {
		t.Skip("symlink test")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"peers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "trusted-devices.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestDeletePeerSynchronizesBothProductionTrustStores(t *testing.T) {
	for _, name := range []string{"trusted-clients.json", "trusted-devices.json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			store, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			peer := Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "peer", Fingerprint: "SHA256:aaaaaaaa"}
			if err := store.Put(peer); err != nil {
				t.Fatal(err)
			}
			syncs := 0
			store.commitHooks.syncDirectory = func(dir string) error {
				syncs++
				return syncPairingDirectory(dir)
			}
			got, deleted, err := store.DeletePeer(peer.ID)
			if err != nil || !deleted || got.ID != peer.ID {
				t.Fatalf("delete: %+v %v %v", got, deleted, err)
			}
			if syncs != 1 {
				t.Fatalf("parent directory sync count=%d, want 1", syncs)
			}
			reopened, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := reopened.Get(peer.ID); ok {
				t.Fatal("revoked peer survived durable replacement")
			}
		})
	}
}

func TestDeletePeerDistinguishesPreCommitAndUncertainDurability(t *testing.T) {
	for _, name := range []string{"trusted-clients.json", "trusted-devices.json"} {
		t.Run(name, func(t *testing.T) {
			newStore := func() (*Store, string, Peer) {
				path := filepath.Join(t.TempDir(), name)
				store, err := Open(path)
				if err != nil {
					t.Fatal(err)
				}
				peer := Peer{ID: "wd_bbbbbbbbbbbbbbbb", Name: "peer", Fingerprint: "SHA256:bbbbbbbb"}
				if err := store.Put(peer); err != nil {
					t.Fatal(err)
				}
				return store, path, peer
			}
			t.Run("pre-commit", func(t *testing.T) {
				store, path, peer := newStore()
				store.commitHooks.beforeReplace = func() error { return errors.New("injected before replacement") }
				_, deleted, err := store.DeletePeer(peer.ID)
				if err == nil || deleted || errors.Is(err, ErrTrustStoreCommitUncertain) {
					t.Fatalf("pre-commit result deleted=%v err=%v", deleted, err)
				}
				reopened, openErr := Open(path)
				if openErr != nil {
					t.Fatal(openErr)
				}
				if _, ok := reopened.Get(peer.ID); !ok {
					t.Fatal("pre-commit failure removed peer")
				}
			})
			t.Run("post-commit-sync", func(t *testing.T) {
				store, path, peer := newStore()
				store.commitHooks.syncDirectory = func(string) error { return errors.New("injected directory sync failure") }
				_, deleted, err := store.DeletePeer(peer.ID)
				if err == nil || deleted || !errors.Is(err, ErrTrustStoreCommitUncertain) {
					t.Fatalf("uncertain result deleted=%v err=%v", deleted, err)
				}
				reopened, openErr := Open(path)
				if openErr != nil {
					t.Fatal(openErr)
				}
				if _, ok := reopened.Get(peer.ID); ok {
					t.Fatal("visible replacement still contains revoked peer")
				}
			})
			t.Run("after-replace", func(t *testing.T) {
				store, path, peer := newStore()
				store.commitHooks.afterReplace = func() error { return errors.New("injected after replacement failure") }
				_, deleted, err := store.DeletePeer(peer.ID)
				if err == nil || deleted || !errors.Is(err, ErrTrustStoreCommitUncertain) {
					t.Fatalf("post-replacement result deleted=%v err=%v", deleted, err)
				}
				reopened, openErr := Open(path)
				if openErr != nil {
					t.Fatal(openErr)
				}
				if _, ok := reopened.Get(peer.ID); ok {
					t.Fatal("replacement was not visible after injected post-replacement failure")
				}
			})
		})
	}
}

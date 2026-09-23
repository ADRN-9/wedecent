package routercontrol

import "testing"

func TestFileControllerTrustReloadsAddAndRevoke(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	source, err := NewFileControllerTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	controller := routerControlTestIdentity(t, "controller")
	peer := routerControlPeer(t, controller)

	if _, ok := source.Get(peer.ID); ok {
		t.Fatal("controller unexpectedly trusted before provisioning")
	}

	store, err := OpenControllerTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}
	got, ok := source.Get(peer.ID)
	if !ok || got.Fingerprint != peer.Fingerprint {
		t.Fatalf("reloaded controller = %+v, ok=%v", got, ok)
	}

	removed, err := store.Delete(peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("controller was not removed")
	}
	if _, ok := source.Get(peer.ID); ok {
		t.Fatal("revoked controller remained authorized")
	}
}

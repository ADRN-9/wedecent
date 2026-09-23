package main

import (
	"errors"
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/trust"
)

func TestRunClientsRevokeRemovesClientTrust(t *testing.T) {
	state := t.TempDir()
	path := filepath.Join(state, "trusted-clients.json")
	store, err := trust.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := trust.Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}

	if err := runClientsRevoke([]string{"--state", state, peer.ID}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(peer.ID); ok {
		t.Fatal("client remained trusted after revoke")
	}
}

func TestRunClientsRevokeRejectsUnknownClient(t *testing.T) {
	state := t.TempDir()
	err := runClientsRevoke([]string{"--state", state, "wd_aaaaaaaaaaaaaaaa"})
	if !errors.Is(err, trust.ErrPeerNotFound) {
		t.Fatalf("error = %v, want ErrPeerNotFound", err)
	}
}

func TestRunClientsRevokeDoesNotTouchOtherTrustDomains(t *testing.T) {
	state := t.TempDir()
	clientPath := filepath.Join(state, "trusted-clients.json")
	routePath := filepath.Join(state, "trusted-route-routers.json")
	clientStore, err := trust.Open(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	routeStore, err := trust.Open(routePath)
	if err != nil {
		t.Fatal(err)
	}
	client := trust.Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "client", Fingerprint: "fp-a"}
	router := trust.Peer{ID: "wd_bbbbbbbbbbbbbbbb", Name: "router", Fingerprint: "fp-b"}
	if err := clientStore.Put(client); err != nil {
		t.Fatal(err)
	}
	if err := routeStore.Put(router); err != nil {
		t.Fatal(err)
	}

	if err := runClientsRevoke([]string{"--state", state, client.ID}); err != nil {
		t.Fatal(err)
	}
	if got, ok := routeStore.Get(router.ID); !ok || got.Fingerprint != router.Fingerprint {
		t.Fatal("terminal client revocation modified route trust")
	}
}

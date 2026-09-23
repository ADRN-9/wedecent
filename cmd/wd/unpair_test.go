package main

import (
	"errors"
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/trust"
)

func TestRunUnpairRemovesLocalDeviceTrust(t *testing.T) {
	state := t.TempDir()
	path := filepath.Join(state, "trusted-devices.json")
	store, err := trust.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	peer := trust.Peer{ID: "wd_aaaaaaaaaaaaaaaa", Name: "device", Fingerprint: "fp-a"}
	if err := store.Put(peer); err != nil {
		t.Fatal(err)
	}

	if err := runUnpair([]string{"--state", state, peer.ID}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(peer.ID); ok {
		t.Fatal("device remained trusted after unpair")
	}
}

func TestRunUnpairRejectsUnknownDevice(t *testing.T) {
	state := t.TempDir()
	err := runUnpair([]string{"--state", state, "wd_aaaaaaaaaaaaaaaa"})
	if !errors.Is(err, trust.ErrPeerNotFound) {
		t.Fatalf("error = %v, want ErrPeerNotFound", err)
	}
}

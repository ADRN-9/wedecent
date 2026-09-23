package main

import (
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/routercontrol"
	"wedecent.com/wedecent/internal/trust"
)

func controllerTestIdentity(t *testing.T, name string) *identity.Identity {
	t.Helper()
	id, err := identity.Ensure(t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func controllerTestFingerprint(t *testing.T, id *identity.Identity) string {
	t.Helper()
	fingerprint, err := identity.FingerprintPublicKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func TestRunTrustStoresDedicatedController(t *testing.T) {
	stateDir := t.TempDir()
	controller := controllerTestIdentity(t, "controller")
	fingerprint := controllerTestFingerprint(t, controller)

	if err := runTrust(stateDir, []string{
		"--id", controller.ID,
		"--fingerprint", fingerprint,
		"--name", "Desktop Core",
	}); err != nil {
		t.Fatal(err)
	}

	store, err := trust.Open(filepath.Join(stateDir, routercontrol.ControllerTrustFile))
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := store.Get(controller.ID)
	if !ok {
		t.Fatal("controller was not stored")
	}
	if peer.Fingerprint != fingerprint || peer.Name != "Desktop Core" {
		t.Fatalf("stored controller = %+v", peer)
	}
}

func TestRunTrustRequiresExplicitFingerprintRotation(t *testing.T) {
	stateDir := t.TempDir()
	controller := controllerTestIdentity(t, "controller")
	other := controllerTestIdentity(t, "other")
	fingerprint := controllerTestFingerprint(t, controller)
	otherFingerprint := controllerTestFingerprint(t, other)

	if err := runTrust(stateDir, []string{
		"--id", controller.ID,
		"--fingerprint", fingerprint,
	}); err != nil {
		t.Fatal(err)
	}
	if err := runTrust(stateDir, []string{
		"--id", controller.ID,
		"--fingerprint", otherFingerprint,
	}); err == nil {
		t.Fatal("fingerprint rotation succeeded without --replace")
	}
	if err := runTrust(stateDir, []string{
		"--id", controller.ID,
		"--fingerprint", otherFingerprint,
		"--replace",
	}); err != nil {
		t.Fatalf("explicit fingerprint rotation failed: %v", err)
	}
}

func TestRunTrustRejectsFingerprintAlias(t *testing.T) {
	stateDir := t.TempDir()
	controller := controllerTestIdentity(t, "controller")
	fingerprint := controllerTestFingerprint(t, controller)

	if err := runTrust(stateDir, []string{
		"--id", controller.ID,
		"--fingerprint", fingerprint,
	}); err != nil {
		t.Fatal(err)
	}
	if err := runTrust(stateDir, []string{
		"--id", "wd_othercontroller",
		"--fingerprint", fingerprint,
	}); err == nil {
		t.Fatal("fingerprint alias was accepted")
	}
}

func TestRunRevokeRemovesController(t *testing.T) {
	stateDir := t.TempDir()
	controller := controllerTestIdentity(t, "controller")
	fingerprint := controllerTestFingerprint(t, controller)
	if err := runTrust(stateDir, []string{
		"--id", controller.ID,
		"--fingerprint", fingerprint,
	}); err != nil {
		t.Fatal(err)
	}

	if err := runRevoke(stateDir, []string{"--id", controller.ID}); err != nil {
		t.Fatal(err)
	}
	store, err := routercontrol.OpenControllerTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(controller.ID); ok {
		t.Fatal("controller remained trusted after revoke")
	}
	if err := runRevoke(stateDir, []string{"--id", controller.ID}); err == nil {
		t.Fatal("second revoke unexpectedly succeeded")
	}
}

func TestRunTrustRejectsInvalidFingerprintBeforeMutation(t *testing.T) {
	stateDir := t.TempDir()
	if err := runTrust(stateDir, []string{
		"--id", "wd_controller",
		"--fingerprint", "not-a-fingerprint",
	}); err == nil {
		t.Fatal("invalid fingerprint was accepted")
	}

	store, err := routercontrol.OpenControllerTrust(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if peers := store.List(); len(peers) != 0 {
		t.Fatalf("invalid trust request mutated store: %+v", peers)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run([]string{"unknown"}); err == nil {
		t.Fatal("unknown command was accepted")
	}
}

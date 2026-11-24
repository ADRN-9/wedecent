package coreprocess

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/portforward"
)

func TestOpenRuntimeForwardingRequiresIndependentReplayAuthority(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := identity.Ensure(stateDir, "core-forwarding-test"); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenRuntime(Config{
		ClientStateDir: stateDir,
		Forwarding: &portforward.ManagerConfig{
			AuthorizationPublicKey: publicKey,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "independent replay endpoint and public Data API key are required") {
		t.Fatalf("missing independent replay authority error = %v", err)
	}
}

func TestOpenRuntimeRejectsLegacyReplayArtifactsBeforeRemoteSetup(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := identity.Ensure(stateDir, "core-forwarding-test"); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(stateDir, "portforward-replay.json")
	if err := os.WriteFile(legacyPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = OpenRuntime(Config{
		ClientStateDir: stateDir,
		Forwarding: &portforward.ManagerConfig{
			AuthorizationPublicKey: publicKey,
		},
		ForwardingReplayEndpoint: "https://replay.example.test/functions/v1/port-forward-replay",
		ForwardingReplayAPIKey:   "public-anon-key",
	})
	if err == nil || !strings.Contains(err.Error(), "offline preservation") {
		t.Fatalf("legacy replay artifact error = %v", err)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy replay artifact was modified or removed: %v", err)
	}
}

func TestOpenRuntimeRejectsUnwitnessedProductionReplay(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := identity.Ensure(stateDir, "core-forwarding-test"); err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenRuntime(Config{
		ClientStateDir: stateDir,
		Forwarding: &portforward.ManagerConfig{
			AuthorizationPublicKey: publicKey,
			Limits:                 portforward.DefaultManagerLimits(),
		},
		ForwardingReplayEndpoint: "https://replay.example.test/functions/v1/port-forward-replay",
		ForwardingReplayAPIKey:   "public-anon-key",
	})
	if err == nil || !strings.Contains(err.Error(), "independently administered witnessed replay adapter") {
		t.Fatalf("unwitnessed production replay was not rejected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "portforward-replay.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Local Core created a local replay fallback: %v", err)
	}
}

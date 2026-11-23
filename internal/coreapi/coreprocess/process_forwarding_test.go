package coreprocess

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
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
	called := false
	previousFactory := newLocalCoreRemoteReplay
	newLocalCoreRemoteReplay = func(string, string, mesh.DeviceID, crypto.Signer) (*portforward.RemoteReplay, error) {
		called = true
		return nil, errors.New("remote replay factory must not run")
	}
	defer func() { newLocalCoreRemoteReplay = previousFactory }()
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
	if called {
		t.Fatal("Local Core attempted remote setup before rejecting legacy replay artifacts")
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy replay artifact was modified or removed: %v", err)
	}
}

func TestOpenRuntimeInjectsIdentityBoundRemoteReplayVerifier(t *testing.T) {
	stateDir := t.TempDir()
	created, err := identity.Ensure(stateDir, "core-forwarding-test")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	previousFactory := newLocalCoreRemoteReplay
	newLocalCoreRemoteReplay = func(endpoint, apiKey string, deviceID mesh.DeviceID, signer crypto.Signer) (*portforward.RemoteReplay, error) {
		called = true
		if endpoint != "https://replay.example.test/functions/v1/port-forward-replay" || apiKey != "public-anon-key" {
			t.Fatalf("replay endpoint/key = %q / %q", endpoint, apiKey)
		}
		if deviceID != mesh.DeviceID(created.ID) {
			t.Fatalf("replay device ID = %q, want %q", deviceID, created.ID)
		}
		signerPublic, ok := signer.Public().(ed25519.PublicKey)
		if !ok || !signerPublic.Equal(created.PublicKey) {
			t.Fatal("Local Core did not pass the loaded device identity signer")
		}
		return portforward.NewRemoteReplay(endpoint, apiKey, deviceID, signer)
	}
	defer func() { newLocalCoreRemoteReplay = previousFactory }()
	runtime, err := OpenRuntime(Config{
		ClientStateDir: stateDir,
		Forwarding: &portforward.ManagerConfig{
			AuthorizationPublicKey: publicKey,
			Limits:                 portforward.DefaultManagerLimits(),
		},
		ForwardingReplayEndpoint: "https://replay.example.test/functions/v1/port-forward-replay",
		ForwardingReplayAPIKey:   "public-anon-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if !called || runtime.Forwarding == nil {
		t.Fatal("Local Core did not compose a forwarding manager with the remote replay verifier")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "portforward-replay.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Local Core created a file-backed replay store: %v", err)
	}
}

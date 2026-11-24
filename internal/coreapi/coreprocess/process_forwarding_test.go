package coreprocess

import (
	"context"
	"crypto/ed25519"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/portforward"
)

func TestOpenRuntimeForwardingRequiresWitnessedCheckpointAuthority(t *testing.T) {
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
	if err == nil || !strings.Contains(err.Error(), "witnessed checkpoint provider and independently authenticated endpoint membership resolver") {
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
	if err == nil || !strings.Contains(err.Error(), "legacy single-provider replay path") {
		t.Fatalf("unwitnessed production replay was not rejected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "portforward-replay.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Local Core created a local replay fallback: %v", err)
	}
}

type coreProcessCheckpointPrimary struct{}

func (coreProcessCheckpointPrimary) Consume(context.Context, portforward.CheckpointRequest) (portforward.CheckpointResult, error) {
	return portforward.CheckpointResult{}, portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointPrimary) Revoke(context.Context, portforward.CheckpointEndpoint, uint64) error {
	return portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointPrimary) Head(context.Context, portforward.CheckpointEndpoint) (portforward.CheckpointHead, error) {
	return portforward.CheckpointHead{}, portforward.ErrCheckpointUnavailable
}

type coreProcessCheckpointWitness struct{}

func (coreProcessCheckpointWitness) Commit(context.Context, portforward.CheckpointRequest, portforward.CheckpointReceipt) (portforward.CheckpointWitnessReceipt, error) {
	return portforward.CheckpointWitnessReceipt{}, portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointWitness) Revoke(context.Context, portforward.CheckpointEndpoint, uint64) (portforward.CheckpointWitnessReceipt, error) {
	return portforward.CheckpointWitnessReceipt{}, portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointWitness) Acknowledge(context.Context, portforward.CheckpointRequest, portforward.CheckpointReceipt) (portforward.CheckpointWitnessAck, error) {
	return portforward.CheckpointWitnessAck{}, portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointWitness) Head(context.Context, portforward.CheckpointWitnessScope) (portforward.CheckpointWitnessHead, error) {
	return portforward.CheckpointWitnessHead{}, portforward.ErrCheckpointUnavailable
}

type coreProcessMembershipResolver struct{}

func (coreProcessMembershipResolver) ResolveCheckpointMembership(context.Context, mesh.DeviceID) (portforward.CheckpointEndpoint, error) {
	return portforward.CheckpointEndpoint{}, portforward.ErrCheckpointRevoked
}

func TestLocalCoreWiresOnlyWitnessedCheckpointReplay(t *testing.T) {
	stateDir := t.TempDir()
	created, err := identity.Ensure(stateDir, "core-witnessed-forwarding-test")
	if err != nil {
		t.Fatal(err)
	}
	controlPlaneKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	primaryPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnesses := make([]portforward.CheckpointWitnessTrust, 3)
	for i := range witnesses {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		witnesses[i] = portforward.CheckpointWitnessTrust{
			Witness: coreProcessCheckpointWitness{},
			ID:      []string{"witness-a", "witness-b", "witness-c"}[i],
			PublicKey: publicKey,
		}
	}
	provider := &portforward.WitnessedReplayCheckpointProvider{
		Primary: coreProcessCheckpointPrimary{},
		PrimaryKey: primaryPublic,
		Witnesses: witnesses,
		Quorum: 2,
	}
	verifier, err := newLocalCoreForwardingVerifier(
		stateDir,
		mesh.DeviceID(created.ID),
		created.PrivateKey,
		controlPlaneKey,
		provider,
		coreProcessMembershipResolver{},
		nil,
		"",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := verifier.Replay.(portforward.VerifiedAuthorizationReplayStore); !ok {
		t.Fatal("Local Core did not bind the complete verified capability to witnessed checkpoint replay")
	}
	if provider.Pending != nil {
		t.Fatal("Local Core mutated the caller's checkpoint provider instead of installing its own durable journal copy")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "portforward-checkpoint-pending.json")); err != nil {
		t.Fatalf("Local Core did not create its protected pending journal: %v", err)
	}
}

type coreProcessCheckpointPrimary struct{}

func (coreProcessCheckpointPrimary) Consume(context.Context, portforward.CheckpointRequest) (portforward.CheckpointResult, error) {
	return portforward.CheckpointResult{}, portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointPrimary) Revoke(context.Context, portforward.CheckpointEndpoint, uint64) error {
	return portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointPrimary) Head(context.Context, portforward.CheckpointEndpoint) (portforward.CheckpointHead, error) {
	return portforward.CheckpointHead{}, portforward.ErrCheckpointUnavailable
}

type coreProcessCheckpointWitness struct{}

func (coreProcessCheckpointWitness) Commit(context.Context, portforward.CheckpointRequest, portforward.CheckpointReceipt) (portforward.CheckpointWitnessReceipt, error) {
	return portforward.CheckpointWitnessReceipt{}, portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointWitness) Revoke(context.Context, portforward.CheckpointEndpoint, uint64) (portforward.CheckpointWitnessReceipt, error) {
	return portforward.CheckpointWitnessReceipt{}, portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointWitness) Acknowledge(context.Context, portforward.CheckpointRequest, portforward.CheckpointReceipt) (portforward.CheckpointWitnessAck, error) {
	return portforward.CheckpointWitnessAck{}, portforward.ErrCheckpointUnavailable
}
func (coreProcessCheckpointWitness) Head(context.Context, portforward.CheckpointWitnessScope) (portforward.CheckpointWitnessHead, error) {
	return portforward.CheckpointWitnessHead{}, portforward.ErrCheckpointUnavailable
}

type coreProcessMembershipResolver struct{}

func (coreProcessMembershipResolver) ResolveCheckpointMembership(context.Context, mesh.DeviceID) (portforward.CheckpointEndpoint, error) {
	return portforward.CheckpointEndpoint{}, portforward.ErrCheckpointRevoked
}

func TestLocalCoreWiresWitnessedCheckpointReplay(t *testing.T) {
	stateDir := t.TempDir()
	created, err := identity.Ensure(stateDir, "core-witnessed-forwarding-test")
	if err != nil {
		t.Fatal(err)
	}
	controlPlaneKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	primaryPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnesses := make([]portforward.CheckpointWitnessTrust, 3)
	for i := range witnesses {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		witnesses[i] = portforward.CheckpointWitnessTrust{
			Witness: coreProcessCheckpointWitness{},
			ID: []string{"witness-a", "witness-b", "witness-c"}[i],
			PublicKey: publicKey,
		}
	}
	provider := &portforward.WitnessedReplayCheckpointProvider{
		Primary: coreProcessCheckpointPrimary{}, PrimaryKey: primaryPublic,
		Witnesses: witnesses, Quorum: 2,
	}
	verifier, err := newLocalCoreForwardingVerifier(
		stateDir, mesh.DeviceID(created.ID), created.PrivateKey, controlPlaneKey,
		provider, coreProcessMembershipResolver{}, nil, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := verifier.Replay.(portforward.VerifiedAuthorizationReplayStore); !ok {
		t.Fatal("Local Core did not bind the complete verified capability to witnessed checkpoint replay")
	}
	if provider.Pending != nil {
		t.Fatal("Local Core mutated the caller's checkpoint provider instead of installing its own durable journal copy")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "portforward-checkpoint-pending.json")); err != nil {
		t.Fatalf("Local Core did not create its protected pending journal: %v", err)
	}
}

package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

type serverFenceWitnessStub struct{}

func (serverFenceWitnessStub) CommitFence(context.Context, CheckpointFenceToken) (CheckpointFenceAcknowledgement, error) {
	return CheckpointFenceAcknowledgement{}, ErrCheckpointUnavailable
}

func (serverFenceWitnessStub) LoadFence(context.Context, CheckpointWitnessScope, uint64) (CheckpointFenceAcknowledgement, bool, error) {
	return CheckpointFenceAcknowledgement{}, false, ErrCheckpointUnavailable
}

func TestNewSupabaseWitnessedReplayCheckpointProviderUsesAtomicServerPrimary(t *testing.T) {
	replay := newDeterministicCheckpointProvider(t)
	replayProvider, _ := newWitnessedFixture(t, replay, NewMemoryCheckpointPendingStore())
	replayFence := newTestFenceCoordinator(t, replay)
	replayPrimary := replayFence.Primary.(*testAtomicCheckpointPrimary)

	_, fencePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	revocationPublic, revocationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controlPlanePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fenceTrust := make([]CheckpointFenceWitnessTrust, 3)
	fenceClients := make([]CheckpointFenceWitnessClient, 3)
	fenceIDs := []string{"postgres-fence-a", "postgres-fence-b", "postgres-fence-c"}
	for i, id := range fenceIDs {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fenceTrust[i] = CheckpointFenceWitnessTrust{ID: id, PublicKey: publicKey}
		fenceClients[i] = CheckpointFenceWitnessClient{ID: id, PublicKey: publicKey, Witness: serverFenceWitnessStub{}}
	}

	config := SupabaseWitnessedReplayCheckpointConfig{
		ReplayPrimary:    replayPrimary,
		ReplayPrimaryKey: append(ed25519.PublicKey(nil), replay.private.Public().(ed25519.PublicKey)...),
		ReplayWitnesses:  replayProvider.Witnesses,
		ReplayQuorum:     2,
		Pending:          NewMemoryCheckpointPendingStore(),
		FencePrimary: SupabaseCheckpointFenceConfig{
			Hostname: "fence.example.test", Port: 443, SPKISHA256Pins: strings.Repeat("a", 64), AnonAPIKey: "test-anon-api-key",
			AuthorityTokenSource: c203StaticAuthorityTokenSource(c203AuthorityJWT("11111111-1111-4111-8111-111111111111")), ActorID: "11111111-1111-4111-8111-111111111111",
			PrimarySigner:              fencePrivate,
			CheckpointHeadKey:          append(ed25519.PublicKey(nil), replay.private.Public().(ed25519.PublicKey)...),
			RevocationAuthorizationKey: revocationPublic,
			WitnessSetVersion:          "postgres-fence-v1", Witnesses: fenceTrust,
		},
		FenceWitnesses:               fenceClients,
		RevocationProofs:             testCheckpointRevocationProofProvider{privateKey: revocationPrivate},
		ControlPlaneAuthorizationKey: controlPlanePublic,
	}
	provider, err := NewSupabaseWitnessedReplayCheckpointProvider(config)
	if err != nil {
		t.Fatalf("server-side PostgreSQL provider composition failed: %v", err)
	}
	if _, ok := provider.Fencing.Primary.(*SupabaseCheckpointFencePrimary); !ok {
		t.Fatal("provider did not install the PostgreSQL atomic fence primary")
	}
	if _, ok := provider.Fencing.Primary.(CheckpointFenceAtomicPrimary); !ok {
		t.Fatal("provider primary does not implement atomic participant-head reservation and commit")
	}
	if err := provider.ValidateConfiguration(); err != nil {
		t.Fatalf("composed provider is not valid: %v", err)
	}

	config.ControlPlaneAuthorizationKey = append(ed25519.PublicKey(nil), revocationPublic...)
	if _, err := NewSupabaseWitnessedReplayCheckpointProvider(config); err == nil {
		t.Fatal("control-plane and revocation proof trust domains were allowed to share a key")
	}
}

package portforward

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestCheckpointAuthorityRestartAndHeadReconciliation(t *testing.T) {
	provider := newDeterministicCheckpointProvider(t)
	request, _, _, initiator, _ := makeCheckpointFixture(t, provider,
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222")
	receipt, err := provider.Consume(context.Background(), request)
	if err != nil { t.Fatal(err) }

	// Model a process restart over the same durable provider state and signing identity.
	restarted := &deterministicCheckpointProvider{
		private: provider.private, keyID: provider.keyID, members: provider.members,
		ledgers: provider.ledgers, available: true, primaryDB: provider.primaryDB,
	}
	head, err := restarted.Head(context.Background(), initiator)
	if err != nil { t.Fatal(err) }
	if err := VerifyCheckpointHead(head, initiator, restarted.private.Public().(ed25519.PublicKey)); err != nil { t.Fatal(err) }
	if head.Generation != receipt.Generation || head.RecordHash != receipt.RecordHash {
		t.Fatal("recovered checkpoint head does not reconcile with durable receipt")
	}
	recovered, err := restarted.Consume(context.Background(), request)
	if err != nil { t.Fatal(err) }
	if CheckpointReceiptDigest(recovered) != CheckpointReceiptDigest(receipt) {
		t.Fatal("restart did not recover the exact idempotent receipt")
	}
}

func TestCheckpointCorruptReceiptAndStaleRevocationFailClosed(t *testing.T) {
	provider := newDeterministicCheckpointProvider(t)
	request, _, _, initiator, _ := makeCheckpointFixture(t, provider,
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222")
	provider.corruptReceipt = true
	corrupt, err := provider.Consume(context.Background(), request)
	if err != nil { t.Fatal(err) }
	if err := VerifyCheckpointReceipt(corrupt, request, provider.private.Public().(ed25519.PublicKey)); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("corrupt receipt accepted: %v", err)
	}

	if err := provider.Revoke(context.Background(), initiator, 1); err != nil { t.Fatal(err) }
	head, err := provider.Head(context.Background(), initiator)
	if err != nil { t.Fatal(err) }
	if err := VerifyCheckpointHead(head, initiator, provider.private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("signed newer revocation epoch should be reconcilable: %v", err)
	}
	if head.RevocationEpoch != 1 { t.Fatalf("revocation epoch=%d", head.RevocationEpoch) }
}

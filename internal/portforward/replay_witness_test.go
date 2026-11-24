package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
)

func newWitnessedFixture(t *testing.T, primary *deterministicCheckpointProvider, pending CheckpointPendingStore) (*WitnessedReplayCheckpointProvider, []*deterministicCheckpointWitness) {
	t.Helper()
	publicKey := primary.private.Public().(ed25519.PublicKey)
	witnesses := make([]*deterministicCheckpointWitness, 3)
	trust := make([]CheckpointWitnessTrust, 3)
	for i := range witnesses {
		witnesses[i] = newDeterministicCheckpointWitness([]string{"witness-a", "witness-b", "witness-c"}[i], publicKey)
		trust[i] = CheckpointWitnessTrust{Witness: witnesses[i], ID: witnesses[i].id, PublicKey: witnesses[i].private.Public().(ed25519.PublicKey)}
	}
	return &WitnessedReplayCheckpointProvider{Primary: primary, PrimaryKey: publicKey, Witnesses: trust, Quorum: 2, Pending: pending}, witnesses
}

func nextCheckpointRequest(t *testing.T, request CheckpointRequest, signer ed25519.PrivateKey, jti string) CheckpointRequest {
	t.Helper()
	request.JTI = jti
	request, err := SignCheckpointRequest(signer, request)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestWitnessConfigurationRejectsPrimarySigningKeyReuse(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	client, _ := newWitnessedFixture(t, primary, NewMemoryCheckpointPendingStore())
	client.Witnesses[0].PublicKey = append(ed25519.PublicKey(nil), primary.private.Public().(ed25519.PublicKey)...)
	if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatalf("primary key reused as independent witness: %v", err)
	}
}

func TestIndependentWitnessQuorumAndPendingReceipt(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	pending := NewMemoryCheckpointPendingStore()
	client, witnesses := newWitnessedFixture(t, primary, pending)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	result, err := client.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.WitnessReceipts) < client.Quorum {
		t.Fatalf("witness receipts=%d", len(result.WitnessReceipts))
	}
	for _, receipt := range result.WitnessReceipts {
		var witnessKey ed25519.PublicKey
		for _, witness := range witnesses {
			if witness.id == receipt.WitnessID {
				witnessKey = witness.private.Public().(ed25519.PublicKey)
			}
		}
		forged := receipt
		forged.Signature = append([]byte(nil), receipt.Signature...)
		forged.Signature[0] ^= 0xff
		if VerifyCheckpointWitnessReceipt(forged, receipt.WitnessID, witnessKey) == nil {
			t.Fatal("forged witness receipt accepted")
		}
		found := false
		for _, witness := range witnesses {
			if witness.id == receipt.WitnessID {
				if err := VerifyCheckpointWitnessReceipt(receipt, witness.id, witness.private.Public().(ed25519.PublicKey)); err != nil {
					t.Fatal(err)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("untrusted witness %q", receipt.WitnessID)
		}
	}
	if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointReplay) && !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("resolved operation retried as new session: %v", err)
	}
}

func TestWitnessRejectsPrimaryLedgerAndSigningKeyRollbackTogether(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request1, signer, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	client, _ := newWitnessedFixture(t, primary, NewMemoryCheckpointPendingStore())
	if _, err := client.Consume(context.Background(), request1); err != nil {
		t.Fatal(err)
	}
	key := checkpointLedgerKey{request1.Initiator.DeviceID, request1.Initiator.AccountID, request1.Initiator.OrganizationID}
	snapshot := cloneCheckpointLedger(primary.ledgers[key])
	privateSnapshot := append(ed25519.PrivateKey(nil), primary.private...)
	request2 := nextCheckpointRequest(t, request1, signer, "AAAAAAAAAAAAAAAAAAAAAA")
	if _, err := client.Consume(context.Background(), request2); err != nil {
		t.Fatal(err)
	}

	// Restore the provider's ledger and its matching signing key together.
	primary.ledgers[key] = snapshot
	primary.private = privateSnapshot
	primary.keyID = checkpointProviderKeyID(privateSnapshot.Public().(ed25519.PublicKey))
	// A fresh client journal models an endpoint restored from an old local snapshot.
	restoredClient, _ := newWitnessedFixture(t, primary, NewMemoryCheckpointPendingStore())
	if _, err := restoredClient.Consume(context.Background(), request2); !errors.Is(err, ErrCheckpointHistorical) && !errors.Is(err, ErrCheckpointWitnessRollback) {
		t.Fatalf("provider ledger+key rollback accepted: %v", err)
	}
}

func TestIndependentWitnessLedgerAndSigningKeyRollbackDetected(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request1, signer, _, initiator, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	client, witnesses := newWitnessedFixture(t, primary, NewMemoryCheckpointPendingStore())
	if _, err := client.Consume(context.Background(), request1); err != nil {
		t.Fatal(err)
	}
	scope := witnessScope(initiator)
	oldLedger := *witnesses[0].ledgers[scope]
	oldLedger.used = make(map[string][32]byte, len(witnesses[0].ledgers[scope].used))
	for key, value := range witnesses[0].ledgers[scope].used {
		oldLedger.used[key] = value
	}
	oldPrivate := append(ed25519.PrivateKey(nil), witnesses[0].private...)
	request2 := nextCheckpointRequest(t, request1, signer, "BBBBBBBBBBBBBBBBBBBBBB")
	if _, err := client.Consume(context.Background(), request2); err != nil {
		t.Fatal(err)
	}
	// Restore one witness ledger and its own signing key together. The other
	// independently administered witnesses retain the later monotonic head.
	witnesses[0].ledgers[scope] = &oldLedger
	witnesses[0].private = oldPrivate
	if _, err := client.Head(context.Background(), initiator); !errors.Is(err, ErrCheckpointWitnessDisagreement) {
		t.Fatalf("witness ledger+key rollback not detected: %v", err)
	}
	request3 := nextCheckpointRequest(t, request1, signer, "CCCCCCCCCCCCCCCCCCCCCC")
	if _, err := client.Consume(context.Background(), request3); !errors.Is(err, ErrCheckpointWitnessRollback) {
		t.Fatalf("witness rollback allowed another checkpoint: %v", err)
	}
}

func TestWitnessQuorumLossFailsClosedAndPendingRetryRecovers(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	pending := NewMemoryCheckpointPendingStore()
	client, witnesses := newWitnessedFixture(t, primary, pending)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	witnesses[0].available, witnesses[1].available = false, false
	if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointQuorum) {
		t.Fatalf("quorum loss error=%v", err)
	}
	witnesses[0].available, witnesses[1].available = true, true
	if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("recovered authorization was returned as a new session: %v", err)
	}
}

func TestWitnessedClientRestartRecoversLostPrimaryCommit(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	client, witnesses := newWitnessedFixture(t, primary, store)
	primary.crashAfter = true
	if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointAmbiguous) {
		t.Fatalf("expected ambiguous primary commit, got %v", err)
	}
	restartedStore, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := newWitnessedFixture(t, primary, restartedStore)
	restarted.Witnesses = client.Witnesses
	if _, err := restarted.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("recovered primary authorization was returned as a new session: %v", err)
	}
	if _, err := restarted.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointReplay) && !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("completed operation replay accepted: %v", err)
	}
	_ = witnesses
}

func TestRestoredPendingJournalCannotReplayAcknowledgedReceipt(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if existing, err := store.Begin(context.Background(), request); err != nil || existing {
		t.Fatalf("initial pending write existing=%t err=%v", existing, err)
	}
	oldPending, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := newWitnessedFixture(t, primary, store)
	result, err := client.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.WitnessAcknowledgements) < client.Quorum {
		t.Fatal("witness completion acknowledgements missing")
	}
	// Restore the pre-completion pending file after the operation was acknowledged.
	if err := os.WriteFile(path, oldPending, 0o600); err != nil {
		t.Fatal(err)
	}
	restoredStore, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restored, _ := newWitnessedFixture(t, primary, restoredStore)
	restored.Witnesses = client.Witnesses
	if _, err := restored.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("restored pending journal replayed an acknowledged receipt: %v", err)
	}
}

func TestWitnessHistoryDisagreementAndHistoricalHeadFailClosed(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	client, witnesses := newWitnessedFixture(t, primary, NewMemoryCheckpointPendingStore())
	request, _, _, initiator, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	if _, err := witnesses[0].Revoke(context.Background(), initiator, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Head(context.Background(), initiator); !errors.Is(err, ErrCheckpointWitnessDisagreement) {
		t.Fatalf("witness disagreement not rejected: %v", err)
	}
	if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointWitnessRollback) && !errors.Is(err, ErrCheckpointQuorum) {
		t.Fatalf("stale endpoint epoch accepted: %v", err)
	}
}

func TestFileCheckpointPendingStoreSurvivesRestartAndRejectsHistoricalReceipt(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, signer, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	existing, err := store.Begin(context.Background(), request)
	if err != nil || existing {
		t.Fatalf("first begin existing=%t err=%v", existing, err)
	}
	// Reopen the same durable journal as a new process would.
	restarted, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	existing, err = restarted.Begin(context.Background(), request)
	if err != nil || !existing {
		t.Fatalf("restarted begin existing=%t err=%v", existing, err)
	}
	result, err := primary.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Resolve(context.Background(), request, result.CheckpointReceipt); err != nil {
		t.Fatal(err)
	}
	if existing, err := restarted.Begin(context.Background(), request); err != nil || !existing {
		t.Fatalf("resolved exact request not resumable: existing=%t err=%v", existing, err)
	}
	conflict := request
	conflict.AuthorizationSHA256 = sha256.Sum256([]byte("different capability"))
	conflict, err = SignCheckpointRequest(signer, conflict)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Begin(context.Background(), conflict); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("conflicting JTI accepted: %v", err)
	}
	if err := secureReplayFile(path); err != nil {
		t.Fatalf("pending journal is not protected by platform file permissions/ACL: %v", err)
	}
}

type checkpointMembershipFixture map[string]CheckpointEndpoint

type checkpointFinalizationAuditFixture struct{ outcomes []string }

func (a *checkpointFinalizationAuditFixture) RecordCheckpointFinalization(_ context.Context, _ CheckpointRequest, outcome string) error {
	a.outcomes = append(a.outcomes, outcome)
	return nil
}

func (m checkpointMembershipFixture) ResolveCheckpointMembership(ctx context.Context, id mesh.DeviceID) (CheckpointEndpoint, error) {
	if err := ctx.Err(); err != nil {
		return CheckpointEndpoint{}, err
	}
	endpoint, ok := m[string(id)]
	if !ok {
		return CheckpointEndpoint{}, ErrCheckpointRevoked
	}
	return endpoint, nil
}

func TestBuildCheckpointRequestBindsVerifiedCapabilityAndBothMemberships(t *testing.T) {
	initPublic, initPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.InitiatingDevice = mesh.DeviceID(identity.DeviceID(initPublic))
	claims.DestinationDevice = mesh.DeviceID(identity.DeviceID(destPublic))
	claims.Route.Source = claims.InitiatingDevice
	claims.Route.Destination = claims.DestinationDevice
	claims.Route.Hops[0].From = claims.InitiatingDevice
	claims.Route.Hops[0].To = claims.DestinationDevice
	authorization, err := SignAuthorization(controlPrivate, claims)
	if err != nil {
		t.Fatal(err)
	}
	memberships := checkpointMembershipFixture{
		string(claims.InitiatingDevice):  {DeviceID: string(claims.InitiatingDevice), AccountID: "11111111-1111-4111-8111-111111111111", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 4},
		string(claims.DestinationDevice): {DeviceID: string(claims.DestinationDevice), AccountID: "22222222-2222-4222-8222-222222222222", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 7},
	}
	request, err := BuildCheckpointRequest(context.Background(), authorization, controlPublic, claims.InitiatingDevice, initPrivate, memberships, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if request.JTI != claims.JTI || request.Initiator.RevocationEpoch != 4 || request.Destination.RevocationEpoch != 7 {
		t.Fatal("checkpoint request omitted capability JTI or independently resolved endpoint membership")
	}
	tampered := authorization
	tampered.Claims.DestinationPort++
	if _, err := BuildCheckpointRequest(context.Background(), tampered, controlPublic, claims.InitiatingDevice, initPrivate, memberships, nil, now); !errors.Is(err, ErrAuthorizationSignature) {
		t.Fatalf("tampered capability accepted: %v", err)
	}
}

func TestCheckpointAuthorizationReplayUsesExactVerifiedCapability(t *testing.T) {
	initPublic, initPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(now, DirectionLocal)
	claims.InitiatingDevice = mesh.DeviceID(identity.DeviceID(initPublic))
	claims.DestinationDevice = mesh.DeviceID(identity.DeviceID(destPublic))
	claims.Route.Source = claims.InitiatingDevice
	claims.Route.Destination = claims.DestinationDevice
	claims.Route.Hops[0].From = claims.InitiatingDevice
	claims.Route.Hops[0].To = claims.DestinationDevice
	authorization, err := SignAuthorization(controlPrivate, claims)
	if err != nil {
		t.Fatal(err)
	}
	initiator := CheckpointEndpoint{DeviceID: string(claims.InitiatingDevice), AccountID: "11111111-1111-4111-8111-111111111111", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 4}
	destination := CheckpointEndpoint{DeviceID: string(claims.DestinationDevice), AccountID: "22222222-2222-4222-8222-222222222222", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 7}
	memberships := checkpointMembershipFixture{
		string(claims.InitiatingDevice):  initiator,
		string(claims.DestinationDevice): destination,
	}
	primary := newDeterministicCheckpointProvider(t)
	primary.register(initiator)
	primary.register(destination)
	provider, witnesses := newWitnessedFixture(t, primary, NewMemoryCheckpointPendingStore())
	consumerScope := witnessScope(initiator)
	for _, witness := range witnesses {
		witness.revoked[witnessScope(initiator)] = initiator.RevocationEpoch
		witness.revoked[witnessScope(destination)] = destination.RevocationEpoch
		witness.ledgers[consumerScope] = &deterministicWitnessLedger{
			revocationEpoch: initiator.RevocationEpoch,
			used:            make(map[string][32]byte),
		}
	}
	replay := &CheckpointAuthorizationReplay{
		Provider: provider, ControlPlaneKey: controlPublic, LocalDeviceID: claims.InitiatingDevice,
		DeviceSigner: initPrivate, Memberships: memberships, Now: func() time.Time { return now },
	}
	if err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization); err != nil {
		t.Fatal(err)
	}
	if len(primary.ledgers) != 1 {
		t.Fatal("verified capability did not reach the witnessed primary checkpoint")
	}
	if err := replay.ConsumePortForwardAuthorization(context.Background(), claims.JTI, time.UnixMilli(claims.ExpiresAtUnixMS)); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatalf("bare JTI bypassed capability-bound checkpoint request: %v", err)
	}
	tampered := authorization
	tampered.Claims.DestinationPort++
	if err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), tampered); !errors.Is(err, ErrAuthorizationSignature) {
		t.Fatalf("tampered capability reached witnessed checkpoint: %v", err)
	}
}

func TestPendingJournalCompactionRetainsUnresolvedAndRejectsReplayAfterRestart(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request1, signer, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	request2 := nextCheckpointRequest(t, request1, signer, "DDDDDDDDDDDDDDDDDDDDDD")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(context.Background(), request2); err != nil {
		t.Fatal(err)
	}
	client, _ := newWitnessedFixture(t, primary, store)
	if _, err := client.Consume(context.Background(), request1); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot checkpointPendingSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 1 {
		t.Fatalf("compaction entries=%d, want unresolved operation retained", len(snapshot.Entries))
	}
	if entry, ok := snapshot.Entries[checkpointPendingKey(request2)]; !ok || entry.State != "pending" {
		t.Fatal("unresolved pending operation was discarded during compaction")
	}
	restarted, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restartedClient, _ := newWitnessedFixture(t, primary, restarted)
	restartedClient.Witnesses = client.Witnesses
	if _, err := restartedClient.Consume(context.Background(), request1); !errors.Is(err, ErrCheckpointReplay) && !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("acknowledged operation replay after compaction: %v", err)
	}
	if _, err := restarted.Begin(context.Background(), request2); err != nil {
		t.Fatalf("unresolved operation not recoverable after restart: %v", err)
	}
}

func TestPendingJournalExhaustionFailsClosed(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	store := NewMemoryCheckpointPendingStore()
	for i := 0; i < checkpointPendingMaxEntries; i++ {
		store.entries[fmt.Sprintf("filler-%d", i)] = checkpointPendingEntry{Fingerprint: "00", State: "pending"}
	}
	if _, err := store.Begin(context.Background(), request); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("journal exhaustion did not fail closed: %v", err)
	}
}

// scopeMismatchWitness returns a correctly signed head for a different
// device, account, or organization than the scope requested by the caller.
type scopeMismatchWitness struct {
	*deterministicCheckpointWitness
	dimension string
}

func (w *scopeMismatchWitness) Head(ctx context.Context, requested CheckpointWitnessScope) (CheckpointWitnessHead, error) {
	head, err := w.deterministicCheckpointWitness.Head(ctx, requested)
	if err != nil {
		return CheckpointWitnessHead{}, err
	}
	switch w.dimension {
	case "device":
		head.Scope.DeviceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	case "account":
		head.Scope.AccountID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	case "organization":
		head.Scope.OrganizationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	default:
		return CheckpointWitnessHead{}, ErrCheckpointIntegrity
	}
	head.Signature = ed25519.Sign(w.private, checkpointWitnessHeadMessage(head))
	return head, nil
}

func TestWitnessHeadRejectsSignedWrongScopeFromQuorum(t *testing.T) {
	for _, dimension := range []string{"device", "account", "organization"} {
		t.Run(dimension, func(t *testing.T) {
			primary := newDeterministicCheckpointProvider(t)
			client, witnesses := newWitnessedFixture(t, primary, NewMemoryCheckpointPendingStore())
			_, _, _, initiator, _ := makeCheckpointFixture(t, primary,
				"11111111-1111-4111-8111-111111111111",
				"22222222-2222-4222-8222-222222222222")
			for i := 0; i < 2; i++ {
				client.Witnesses[i].Witness = &scopeMismatchWitness{
					deterministicCheckpointWitness: witnesses[i],
					dimension:                      dimension,
				}
			}
			if _, err := client.Head(context.Background(), initiator); !errors.Is(err, ErrCheckpointQuorum) {
				t.Fatalf("signed out-of-scope heads counted toward quorum: %v", err)
			}
		})
	}
}

func TestWitnessPreflightRejectsSignedWrongScopeFromQuorum(t *testing.T) {
	for _, dimension := range []string{"device", "account", "organization"} {
		t.Run(dimension, func(t *testing.T) {
			primary := newDeterministicCheckpointProvider(t)
			client, witnesses := newWitnessedFixture(t, primary, NewMemoryCheckpointPendingStore())
			request, _, _, _, _ := makeCheckpointFixture(t, primary,
				"11111111-1111-4111-8111-111111111111",
				"22222222-2222-4222-8222-222222222222")
			for i := 0; i < 2; i++ {
				client.Witnesses[i].Witness = &scopeMismatchWitness{
					deterministicCheckpointWitness: witnesses[i],
					dimension:                      dimension,
				}
			}
			if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointQuorum) {
				t.Fatalf("signed out-of-scope preflight heads counted toward quorum: %v", err)
			}
			for _, witness := range witnesses {
				if len(witness.historyFor(witnessScope(request.Initiator))) != 0 {
					t.Fatal("witness commit occurred without an in-scope preflight quorum")
				}
			}
		})
	}
}

func TestFilePendingJournalPersistsVerifiedAcknowledgements(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if existing, err := store.Begin(context.Background(), request); err != nil || existing {
		t.Fatalf("begin existing=%t err=%v", existing, err)
	}
	receiptResult, err := primary.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Resolve(context.Background(), request, receiptResult.CheckpointReceipt); err != nil {
		t.Fatal(err)
	}
	client, witnesses := newWitnessedFixture(t, primary, store)
	if err := client.ValidateConfiguration(); err != nil {
		t.Fatal(err)
	}
	if _, err := witnesses[0].Commit(context.Background(), request, receiptResult.CheckpointReceipt); err != nil {
		t.Fatal(err)
	}
	ack, err := witnesses[0].Acknowledge(context.Background(), request, receiptResult.CheckpointReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAcknowledgement(context.Background(), request, receiptResult.CheckpointReceipt, ack, client.Witnesses[0]); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	acks, err := restarted.LoadAcknowledgements(context.Background(), request, receiptResult.CheckpointReceipt, client.Witnesses)
	if err != nil {
		t.Fatal(err)
	}
	if len(acks) != 1 || acks[0].WitnessID != ack.WitnessID {
		t.Fatalf("persisted acknowledgements=%d", len(acks))
	}
	if existing, err := restarted.Begin(context.Background(), request); err != nil || !existing {
		t.Fatalf("resolved exact retry existing=%t err=%v", existing, err)
	}
	forged := ack
	forged.Signature = append([]byte(nil), ack.Signature...)
	forged.Signature[0] ^= 0xff
	if err := restarted.RecordAcknowledgement(context.Background(), request, receiptResult.CheckpointReceipt, forged, client.Witnesses[0]); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("incorrectly signed acknowledgement accepted: %v", err)
	}
}

type lostWitnessAckResponse struct {
	CheckpointWitness
	loseNext bool
}

func (w *lostWitnessAckResponse) Acknowledge(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt) (CheckpointWitnessAck, error) {
	ack, err := w.CheckpointWitness.Acknowledge(ctx, request, receipt)
	if err != nil {
		return CheckpointWitnessAck{}, err
	}
	if w.loseNext {
		w.loseNext = false
		return CheckpointWitnessAck{}, errors.New("simulated lost acknowledgement response")
	}
	return ack, nil
}

func TestWitnessFinalizationRecoversLostAckResponsesAfterRestart(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	client, witnesses := newWitnessedFixture(t, primary, store)
	client.Witnesses[0].Witness = &lostWitnessAckResponse{CheckpointWitness: witnesses[0], loseNext: true}
	client.Witnesses[1].Witness = &lostWitnessAckResponse{CheckpointWitness: witnesses[1], loseNext: true}
	if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointQuorum) {
		t.Fatalf("first attempt should retain the resolved journal without local quorum: %v", err)
	}
	restartedStore, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &WitnessedReplayCheckpointProvider{
		Primary: primary, PrimaryKey: client.PrimaryKey, Witnesses: client.Witnesses,
		Quorum: client.Quorum, Pending: restartedStore,
	}
	if _, err := restarted.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("top-level exact-request recovery returned a new session: %v", err)
	}
	consumer, ok := checkpointConsumer(request)
	if !ok {
		t.Fatal("request has no checkpoint consumer")
	}
	key := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
	primary.mu.Lock()
	receipt := primary.ledgers[key].used[request.JTI].receipt
	primary.mu.Unlock()
	alreadyAcknowledged := 0
	for _, trust := range restarted.Witnesses {
		ack, err := trust.Witness.Acknowledge(context.Background(), request, receipt)
		if err == nil && VerifyCheckpointWitnessAck(ack, trust.ID, trust.PublicKey) == nil && ack.Status == "already_acknowledged" {
			alreadyAcknowledged++
		}
	}
	if alreadyAcknowledged < restarted.Quorum {
		t.Fatalf("top-level recovery did not finalize authenticated acknowledgement quorum: %d", alreadyAcknowledged)
	}
	if _, err := restarted.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("recovered authorization was returned as a new session: %v", err)
	}
	if len(primary.ledgers) != 1 {
		t.Fatalf("primary authorization ledger changed during finalization recovery: %d", len(primary.ledgers))
	}
}

func TestPendingJournalPartialAcknowledgementPersistenceAndValidation(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	result, err := primary.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Resolve(context.Background(), request, result.CheckpointReceipt); err != nil {
		t.Fatal(err)
	}
	client, witnesses := newWitnessedFixture(t, primary, store)
	if err := client.ValidateConfiguration(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < client.Quorum; i++ {
		if _, err := witnesses[i].Commit(context.Background(), request, result.CheckpointReceipt); err != nil {
			t.Fatal(err)
		}
	}
	acks := make([]CheckpointWitnessAck, client.Quorum)
	for i := range acks {
		acks[i], err = witnesses[i].Acknowledge(context.Background(), request, result.CheckpointReceipt)
		if err != nil {
			t.Fatal(err)
		}
	}
	writes := 0
	store.writeSnapshot = func(path string, value any, pattern string, maxSize int64) error {
		writes++
		if writes == 2 {
			return errors.New("injected acknowledgement persistence failure")
		}
		return writeReplayJSON(path, value, pattern, maxSize)
	}
	if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, acks[0], client.Witnesses[0]); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, acks[1], client.Witnesses[1]); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("partial acknowledgement write did not fail closed: %v", err)
	}
	restarted, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetCheckpointTrustAnchors(client.PrimaryKey, client.Witnesses, client.Quorum); err != nil { t.Fatal(err) }
	persisted, err := restarted.LoadAcknowledgements(context.Background(), request, result.CheckpointReceipt, client.Witnesses)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 1 || persisted[0].WitnessID != acks[0].WitnessID {
		t.Fatalf("partial durable acknowledgements=%d", len(persisted))
	}
	if err := restarted.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, acks[1], client.Witnesses[1]); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, acks[0], client.Witnesses[0]); err != nil {
		t.Fatal(err)
	}
	persisted, err = restarted.LoadAcknowledgements(context.Background(), request, result.CheckpointReceipt, client.Witnesses)
	if err != nil || len(persisted) != client.Quorum {
		t.Fatalf("idempotent duplicate changed evidence count=%d err=%v", len(persisted), err)
	}

	wrongScope := acks[0]
	wrongScope.Scope.AccountID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	wrongScope.Signature = ed25519.Sign(witnesses[0].private, checkpointWitnessAckMessage(wrongScope))
	if err := restarted.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, wrongScope, client.Witnesses[0]); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("correctly signed wrong-scope acknowledgement accepted: %v", err)
	}
	wrongFingerprint := acks[0]
	wrongFingerprint.RequestSHA256[0] ^= 0xff
	wrongFingerprint.Signature = ed25519.Sign(witnesses[0].private, checkpointWitnessAckMessage(wrongFingerprint))
	if err := restarted.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, wrongFingerprint, client.Witnesses[0]); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("correctly signed wrong-fingerprint acknowledgement accepted: %v", err)
	}
}

func TestPendingJournalCompactionInterruptionRetainsQuorumEvidence(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	failCompaction := true
	store.writeSnapshot = func(path string, value any, pattern string, maxSize int64) error {
		snapshot, ok := value.(checkpointPendingSnapshot)
		if !ok {
			return errors.New("unexpected pending snapshot type")
		}
		if len(snapshot.Entries) == 0 && failCompaction {
			failCompaction = false
			return errors.New("injected compaction interruption")
		}
		return writeReplayJSON(path, snapshot, pattern, maxSize)
	}
	client, _ := newWitnessedFixture(t, primary, store)
	if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatalf("compaction interruption did not fail closed: %v", err)
	}
	restarted, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetCheckpointTrustAnchors(client.PrimaryKey, client.Witnesses, client.Quorum); err != nil {
		t.Fatal(err)
	}
	consumer, ok := checkpointConsumer(request)
	if !ok {
		t.Fatal("request has no checkpoint consumer")
	}
	ledgerKey := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
	primary.mu.Lock()
	receipt := primary.ledgers[ledgerKey].used[request.JTI].receipt
	primary.mu.Unlock()
	acks, err := restarted.LoadAcknowledgements(context.Background(), request, receipt, client.Witnesses)
	if err != nil || len(acks) < client.Quorum {
		t.Fatalf("quorum evidence lost across compaction interruption: acks=%d err=%v", len(acks), err)
	}
	restartedClient, _ := newWitnessedFixture(t, primary, restarted)
	restartedClient.Witnesses = client.Witnesses
	if _, err := restartedClient.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("exact retry did not finalize recovered quorum evidence safely: %v", err)
	}
	primary.mu.Lock()
	ledger := primary.ledgers[ledgerKey]
	consumed := len(ledger.used)
	primary.mu.Unlock()
	if consumed != 1 {
		t.Fatalf("primary authorization consumed %d times", consumed)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot checkpointPendingSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 0 {
		t.Fatalf("successful retry did not finish compaction: entries=%d", len(snapshot.Entries))
	}
}

func TestPendingJournalConcurrentFinalizationIsIdempotent(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileCheckpointPendingStore(filepath.Join(dir, "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	client, _ := newWitnessedFixture(t, primary, store)
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := client.Consume(context.Background(), request)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	successes, historical := 0, 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		if errors.Is(err, ErrCheckpointHistorical) || errors.Is(err, ErrCheckpointReplay) {
			historical++
			continue
		}
		t.Fatalf("concurrent finalization failed unexpectedly: %v", err)
	}
	if successes > 1 || successes+historical != 2 {
		t.Fatalf("unsafe concurrent outcomes success=%d historical=%d", successes, historical)
	}
	consumer, ok := checkpointConsumer(request)
	if !ok {
		t.Fatal("request has no checkpoint consumer")
	}
	ledgerKey := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
	primary.mu.Lock()
	ledger := primary.ledgers[ledgerKey]
	consumed := len(ledger.used)
	primary.mu.Unlock()
	if consumed != 1 {
		t.Fatalf("concurrent retry consumed primary capability %d times", consumed)
	}
}

func TestPendingJournalCorruptionAndAmbiguousStateFailClosed(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "malformed-json", data: []byte(`{"version":1,"entries":`)},
		{name: "unknown-state", data: func() []byte {
			fp, _ := CheckpointRequestFingerprint(request)
			snapshot := checkpointPendingSnapshot{Version: checkpointPendingVersion, Entries: map[string]checkpointPendingEntry{
				checkpointPendingKey(request): {Fingerprint: fmt.Sprintf("%x", fp[:]), State: "committing"},
			}}
			data, _ := json.Marshal(snapshot)
			return data
		}()},
		{name: "oversized", data: make([]byte, checkpointPendingMaxSize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := setReplayTestDirectoryOwner(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "pending.json")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := setReplayFileOwner(path); err != nil {
				t.Fatal(err)
			}
			store, err := NewFileCheckpointPendingStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Begin(context.Background(), request); !errors.Is(err, ErrReplayUnavailable) {
				t.Fatalf("corrupt/ambiguous journal accepted: %v", err)
			}
		})
	}
}

func TestWitnessCommitCrashBeforeLocalResolutionRecoversIdempotently(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	failResolve := true
	store.writeSnapshot = func(path string, value any, pattern string, maxSize int64) error {
		snapshot, ok := value.(checkpointPendingSnapshot)
		if !ok {
			return errors.New("unexpected pending snapshot type")
		}
		if failResolve {
			for _, entry := range snapshot.Entries {
				if entry.State == "resolved" {
					failResolve = false
					return errors.New("injected crash after witness commitment")
				}
			}
		}
		return writeReplayJSON(path, value, pattern, maxSize)
	}
	client, witnesses := newWitnessedFixture(t, primary, store)
	if _, err := client.Consume(context.Background(), request); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("local resolution crash did not fail closed: %v", err)
	}
	scope := witnessScope(checkpointEndpointForConsumer(request))
	for _, witness := range witnesses {
		if got := len(witness.historyFor(scope)); got != 1 {
			t.Fatalf("witness %s commitment count before retry=%d", witness.id, got)
		}
	}
	restartedStore, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := newWitnessedFixture(t, primary, restartedStore)
	restarted.Witnesses = client.Witnesses
	if _, err := restarted.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("recovered operation was returned as a new session: %v", err)
	}
	for _, witness := range witnesses {
		if got := len(witness.historyFor(scope)); got != 1 {
			t.Fatalf("witness %s was recommitted after restart: %d", witness.id, got)
		}
	}
	consumer, ok := checkpointConsumer(request)
	if !ok {
		t.Fatal("request has no checkpoint consumer")
	}
	key := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
	primary.mu.Lock()
	used := len(primary.ledgers[key].used)
	primary.mu.Unlock()
	if used != 1 {
		t.Fatalf("primary authorization consumption count=%d", used)
	}
}

func TestExpiredAuthorizationFinalizationRecoversQuorumWithoutReconsuming(t *testing.T) {
	initPublic, initPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Millisecond)
	claims := testRoutedClaims(start, DirectionLocal)
	claims.InitiatingDevice = mesh.DeviceID(identity.DeviceID(initPublic))
	claims.DestinationDevice = mesh.DeviceID(identity.DeviceID(destPublic))
	claims.Route.Source, claims.Route.Destination = claims.InitiatingDevice, claims.DestinationDevice
	claims.Route.Hops[0].From, claims.Route.Hops[0].To = claims.InitiatingDevice, claims.Router
	claims.Route.Hops[1].From, claims.Route.Hops[1].To = claims.Router, claims.DestinationDevice
	claims.ExpiresAtUnixMS = start.Add(20 * time.Second).UnixMilli()
	claims.Route.ExpiresAt = time.UnixMilli(claims.ExpiresAtUnixMS).UTC()
	routeAuthorization, routePublicKey := testRouteAuthorization(t, claims)
	authorization, err := SignAuthorization(controlPrivate, claims)
	if err != nil {
		t.Fatal(err)
	}
	authorization.RouteAuthorization = routeAuthorization
	initiator := CheckpointEndpoint{DeviceID: string(claims.InitiatingDevice), AccountID: "11111111-1111-4111-8111-111111111111", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 4}
	destination := CheckpointEndpoint{DeviceID: string(claims.DestinationDevice), AccountID: "22222222-2222-4222-8222-222222222222", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 7}
	memberships := checkpointMembershipFixture{string(claims.InitiatingDevice): initiator, string(claims.DestinationDevice): destination}
	primary := newDeterministicCheckpointProvider(t)
	primary.register(initiator)
	primary.register(destination)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileCheckpointPendingStore(filepath.Join(dir, "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	failResolve := true
	store.writeSnapshot = func(path string, value any, pattern string, maxSize int64) error {
		if snapshot, ok := value.(checkpointPendingSnapshot); ok && failResolve {
			for _, entry := range snapshot.Entries {
				if entry.State == "resolved" {
					failResolve = false
					return errors.New("injected local resolution failure")
				}
			}
		}
		return writeReplayJSON(path, value, pattern, maxSize)
	}
	provider, witnesses := newWitnessedFixture(t, primary, store)
	for _, witness := range witnesses {
		witness.revoked[witnessScope(initiator)] = initiator.RevocationEpoch
		witness.revoked[witnessScope(destination)] = destination.RevocationEpoch
		witness.ledgers[witnessScope(initiator)] = &deterministicWitnessLedger{revocationEpoch: initiator.RevocationEpoch, used: map[string][32]byte{}}
	}
	now := start
	audit := &checkpointFinalizationAuditFixture{}
	routeReplay := mesh.NewMemoryRouteAuthorizationReplay()
	routeVerifier := MeshCheckpointRouteAuthorizationVerifier{Verifier: mesh.RouteAuthorizationVerifier{KeyID: "route-key-1", PublicKey: routePublicKey, Replay: routeReplay, Now: func() time.Time { return now }}}
	replay := &CheckpointAuthorizationReplay{Provider: provider, ControlPlaneKey: controlPublic, LocalDeviceID: claims.InitiatingDevice, DeviceSigner: initPrivate, Memberships: memberships, RouteVerifier: routeVerifier, FinalizationAuditor: audit, Now: func() time.Time { return now }}
	if err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("injected unresolved journal result: %v", err)
	}
	for _, witness := range witnesses {
		if len(witness.historyFor(witnessScope(initiator))) != 1 {
			t.Fatalf("witness %s did not commit exactly once", witness.id)
		}
	}
	now = time.UnixMilli(claims.ExpiresAtUnixMS).Add(time.Second).UTC()
	if err := replay.FinalizeExpiredPortForwardAuthorization(context.Background(), authorization); err != nil {
		t.Fatalf("expiry-independent finalization failed: %v", err)
	}
	if len(audit.outcomes) != 2 || audit.outcomes[0] != CheckpointFinalizationStarted || audit.outcomes[1] != CheckpointFinalizationComplete {
		t.Fatalf("historical finalization audit outcomes=%v", audit.outcomes)
	}
	consumer, ok := checkpointConsumer(CheckpointRequest{Initiator: initiator, Destination: destination, ConsumingDeviceID: string(claims.InitiatingDevice)})
	if !ok {
		t.Fatal("consumer scope unavailable")
	}
	key := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
	primary.mu.Lock()
	used := len(primary.ledgers[key].used)
	primary.mu.Unlock()
	if used != 1 {
		t.Fatalf("primary capability consumed %d times", used)
	}
	for _, witness := range witnesses {
		if len(witness.historyFor(witnessScope(initiator))) != 1 {
			t.Fatalf("witness %s was committed again during finalization", witness.id)
		}
	}
}
func TestExpiredFinalizationRejectsMembershipRevocationAfterWitnessCommit(t *testing.T) {
	initPublic, initPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Millisecond)
	claims := testClaims(start, DirectionLocal)
	claims.InitiatingDevice = mesh.DeviceID(identity.DeviceID(initPublic))
	claims.DestinationDevice = mesh.DeviceID(identity.DeviceID(destPublic))
	claims.Route.Source, claims.Route.Destination = claims.InitiatingDevice, claims.DestinationDevice
	claims.Route.Hops[0].From, claims.Route.Hops[0].To = claims.InitiatingDevice, claims.DestinationDevice
	claims.ExpiresAtUnixMS = start.Add(20 * time.Second).UnixMilli()
	claims.Route.ExpiresAt = time.UnixMilli(claims.ExpiresAtUnixMS).UTC()
	authorization, err := SignAuthorization(controlPrivate, claims)
	if err != nil {
		t.Fatal(err)
	}
	initiator := CheckpointEndpoint{DeviceID: string(claims.InitiatingDevice), AccountID: "11111111-1111-4111-8111-111111111111", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 4}
	destination := CheckpointEndpoint{DeviceID: string(claims.DestinationDevice), AccountID: "22222222-2222-4222-8222-222222222222", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 7}
	memberships := checkpointMembershipFixture{string(claims.InitiatingDevice): initiator, string(claims.DestinationDevice): destination}
	primary := newDeterministicCheckpointProvider(t)
	primary.register(initiator)
	primary.register(destination)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileCheckpointPendingStore(filepath.Join(dir, "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	failResolve := true
	store.writeSnapshot = func(path string, value any, pattern string, maxSize int64) error {
		if snapshot, ok := value.(checkpointPendingSnapshot); ok && failResolve {
			for _, entry := range snapshot.Entries {
				if entry.State == "resolved" {
					failResolve = false
					return errors.New("injected local resolution failure")
				}
			}
		}
		return writeReplayJSON(path, value, pattern, maxSize)
	}
	provider, witnesses := newWitnessedFixture(t, primary, store)
	for _, witness := range witnesses {
		witness.revoked[witnessScope(initiator)] = initiator.RevocationEpoch
		witness.revoked[witnessScope(destination)] = destination.RevocationEpoch
		witness.ledgers[witnessScope(initiator)] = &deterministicWitnessLedger{revocationEpoch: initiator.RevocationEpoch, used: map[string][32]byte{}}
	}
	now := start
	audit := &checkpointFinalizationAuditFixture{}
	replay := &CheckpointAuthorizationReplay{Provider: provider, ControlPlaneKey: controlPublic, LocalDeviceID: claims.InitiatingDevice, DeviceSigner: initPrivate, Memberships: memberships, FinalizationAuditor: audit, Now: func() time.Time { return now }}
	if err := replay.ConsumeVerifiedPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("injected unresolved journal result: %v", err)
	}
	for _, witness := range witnesses {
		if len(witness.historyFor(witnessScope(initiator))) != 1 {
			t.Fatalf("witness %s did not commit exactly once", witness.id)
		}
	}
	updated := initiator
	updated.RevocationEpoch++
	memberships[string(claims.InitiatingDevice)] = updated
	now = time.UnixMilli(claims.ExpiresAtUnixMS).Add(time.Second).UTC()
	if err := replay.FinalizeExpiredPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrCheckpointRevoked) {
		t.Fatalf("revoked historical operation finalized: %v", err)
	}
	if len(audit.outcomes) != 1 || audit.outcomes[0] != CheckpointFinalizationRevoked {
		t.Fatalf("revocation outcome not auditable: %v", audit.outcomes)
	}
	for _, witness := range witnesses {
		if len(witness.historyFor(witnessScope(initiator))) != 1 {
			t.Fatalf("finalization changed witness history at %s", witness.id)
		}
	}
}
func TestFinalizationRejectsPrimaryOnlyAmbiguousOperation(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	store := NewMemoryCheckpointPendingStore()
	if _, err := store.Begin(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := primary.Consume(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	provider, witnesses := newWitnessedFixture(t, primary, store)
	if err := provider.Finalize(context.Background(), request); !errors.Is(err, ErrCheckpointQuorum) {
		t.Fatalf("primary-only operation was incorrectly finalized: %v", err)
	}
	for _, witness := range witnesses {
		if len(witness.historyFor(witnessScope(checkpointEndpointForConsumer(request)))) != 0 {
			t.Fatalf("finalization created a new witness commitment at %s", witness.id)
		}
	}
	consumer, _ := checkpointConsumer(request)
	key := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
	primary.mu.Lock()
	used := len(primary.ledgers[key].used)
	primary.mu.Unlock()
	if used != 1 {
		t.Fatalf("primary consumption count=%d", used)
	}
}
func TestPendingJournalInterruptedPublicationPreservesPreviousEvidence(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	first, signer, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	second := nextCheckpointRequest(t, first, signer, "EEEEEEEEEEEEEEEEEEEEEE")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store.writeSnapshot = func(string, any, string, int64) error { return errors.New("injected publication interruption") }
	if _, err := store.Begin(context.Background(), second); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("interrupted publication returned %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed publication changed durable journal bytes")
	}
	store.writeSnapshot = nil
	if existing, err := store.Begin(context.Background(), first); err != nil || !existing {
		t.Fatalf("previous pending evidence lost: existing=%t err=%v", existing, err)
	}
}
func TestFilePendingJournalRejectsForgedAcknowledgementInUnrelatedEntry(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, signer, _, _, _ := makeCheckpointFixture(
		t,
		primary,
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
	)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	provider, _ := newWitnessedFixture(t, primary, store)
	if err := provider.ValidateConfiguration(); err != nil {
		t.Fatal(err)
	}
	store.writeSnapshot = func(path string, value any, pattern string, maxSize int64) error {
		if snapshot, ok := value.(checkpointPendingSnapshot); ok && len(snapshot.Entries) == 0 {
			return errors.New("injected compaction publication failure")
		}
		return writeReplayJSON(path, value, pattern, maxSize)
	}
	if _, err := provider.Consume(context.Background(), request); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatalf("expected retained acknowledgement evidence after interrupted compaction: %v", err)
	}
	store.writeSnapshot = nil
	second := nextCheckpointRequest(t, request, signer, "FFFFFFFFFFFFFFFFFFFFFF")
	if _, err := store.Begin(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot checkpointPendingSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	found := false
	for key, entry := range snapshot.Entries {
		if entry.Request.JTI != request.JTI {
			continue
		}
		if len(entry.Acknowledgements) == 0 {
			t.Fatal("expected persisted witness acknowledgement")
		}
		entry.Acknowledgements[0].Signature = append([]byte(nil), entry.Acknowledgements[0].Signature...)
		entry.Acknowledgements[0].Signature[0] ^= 0xff
		snapshot.Entries[key] = entry
		found = true
	}
	if !found {
		t.Fatal("original resolved operation missing from pending journal")
	}
	forged, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setReplayFileOwner(path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(context.Background(), second); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("forged acknowledgement in unrelated entry was accepted: %v", err)
	}
}

func TestFilePendingJournalByteAndEntryExhaustion(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, signer, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	second := nextCheckpointRequest(t, request, signer, "CCCCCCCCCCCCCCCCCCCCCC")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(oversizedPath, make([]byte, 129), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setReplayFileOwner(oversizedPath); err != nil {
		t.Fatal(err)
	}
	oversized, err := NewFileCheckpointPendingStore(oversizedPath)
	if err != nil {
		t.Fatal(err)
	}
	oversized.maxSize = 128
	if _, err := oversized.Begin(context.Background(), request); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("durable byte-size limit did not fail closed: %v", err)
	}
	entryPath := filepath.Join(dir, "entries.json")
	entries, err := NewFileCheckpointPendingStore(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	entries.maxEntries = 1
	if _, err := entries.Begin(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := entries.Begin(context.Background(), second); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("durable entry limit did not fail closed: %v", err)
	}
	data, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot checkpointPendingSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 1 {
		t.Fatalf("entry exhaustion partially published %d entries", len(snapshot.Entries))
	}
}

func TestFilePendingJournalRejectsNestedDuplicateKeysAndUnrelatedCorruption(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, signer, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	second := nextCheckpointRequest(t, request, signer, "DDDDDDDDDDDDDDDDDDDDDD")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(data), `"request":{`, `"request":{"JTI":"forged",`, 1)
	if duplicate == string(data) {
		t.Fatal("could not locate nested request object")
	}
	if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(context.Background(), request); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("nested duplicate JSON key accepted: %v", err)
	}
	path2 := filepath.Join(dir, "unrelated.json")
	store2, err := NewFileCheckpointPendingStore(path2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store2.Begin(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := store2.Begin(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path2)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := string(data)
	index := strings.LastIndex(corrupt, `"state":"pending"`)
	if index < 0 {
		t.Fatal("second pending entry not found")
	}
	corrupt = corrupt[:index] + strings.Replace(corrupt[index:], `"state":"pending"`, `"state":"ambiguous"`, 1)
	if err := os.WriteFile(path2, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store2.Begin(context.Background(), request); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("corruption in unrelated entry was ignored: %v", err)
	}
}
func TestPendingJournalCompactionRequiresDurableAcknowledgements(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileCheckpointPendingStore(filepath.Join(dir, "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	result, err := primary.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Resolve(context.Background(), request, result.CheckpointReceipt); err != nil {
		t.Fatal(err)
	}
	client, witnesses := newWitnessedFixture(t, primary, store)
	if err := client.ValidateConfiguration(); err != nil {
		t.Fatal(err)
	}
	acks := make([]CheckpointWitnessAck, client.Quorum)
	for i := range acks {
		if _, err := witnesses[i].Commit(context.Background(), request, result.CheckpointReceipt); err != nil {
			t.Fatal(err)
		}
		acks[i], err = witnesses[i].Acknowledge(context.Background(), request, result.CheckpointReceipt)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Compact(context.Background(), acks, client.Witnesses, client.Quorum); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAcknowledgements(context.Background(), request, result.CheckpointReceipt, client.Witnesses); err != nil {
		t.Fatalf("ephemeral acknowledgements compacted unresolved durable evidence: %v", err)
	}
	for i := range acks {
		if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, acks[i], client.Witnesses[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Compact(context.Background(), acks, client.Witnesses, client.Quorum); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAcknowledgements(context.Background(), request, result.CheckpointReceipt, client.Witnesses); !errors.Is(err, ErrCheckpointHistorical) {
		t.Fatalf("durably quorum-acknowledged journal entry was not compacted: %v", err)
	}
}

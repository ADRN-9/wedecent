package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	result, err := client.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Disposition != CheckpointRecovered {
		t.Fatalf("disposition=%q", result.Disposition)
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
	result, err := restarted.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Disposition != CheckpointRecovered || len(result.WitnessReceipts) < restarted.Quorum {
		t.Fatalf("restart recovery disposition=%q witnesses=%d", result.Disposition, len(result.WitnessReceipts))
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
	if _, err := restarted.Begin(context.Background(), request); !errors.Is(err, ErrCheckpointReplay) {
		t.Fatalf("resolved historical operation accepted: %v", err)
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
		string(claims.InitiatingDevice): initiator,
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
			used: make(map[string][32]byte),
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

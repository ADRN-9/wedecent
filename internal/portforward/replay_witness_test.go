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
	"reflect"
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

type checkpointFinalizationAuditFixture struct {
	outcomes     []string
	operationIDs []string
	seen         map[string]map[string]bool
}

func (a *checkpointFinalizationAuditFixture) RecordCheckpointFinalization(_ context.Context, _ CheckpointRequest, operationID, outcome string, _ *CheckpointFinalizationEvidence) error {
	if operationID == "" {
		return ErrCheckpointIntegrity
	}
	if a.seen == nil {
		a.seen = make(map[string]map[string]bool)
	}
	if a.seen[operationID] == nil {
		a.seen[operationID] = make(map[string]bool)
	}
	if a.seen[operationID][outcome] {
		return nil
	}
	a.seen[operationID][outcome] = true
	a.operationIDs = append(a.operationIDs, operationID)
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
	if len(snapshot.Entries) != 2 {
		t.Fatalf("compaction entries=%d, want both terminal evidence and unresolved operation retained", len(snapshot.Entries))
	}
	if entry, ok := snapshot.Entries[checkpointPendingKey(request1)]; !ok || entry.State != "resolved" {
		t.Fatal("signed terminal decisions were discarded during compaction")
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
	if err := restarted.SetCheckpointTrustAnchors(client.PrimaryKey, client.Witnesses, client.Quorum); err != nil {
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
	if err := restarted.SetCheckpointTrustAnchors(client.PrimaryKey, client.Witnesses, client.Quorum); err != nil {
		t.Fatal(err)
	}
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
	store.compactHook = func(context.Context) error {
		if failCompaction {
			failCompaction = false
			return errors.New("injected compaction interruption")
		}
		return nil
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
	entry, ok := snapshot.Entries[checkpointPendingKey(request)]
	if !ok || entry.State != "resolved" || committedCheckpointAckCount(entry.Acknowledgements) < client.Quorum {
		t.Fatalf("successful retry discarded terminal evidence: entry=%+v", entry)
	}
}

func TestPendingJournalConcurrentFinalizationAcrossProviderInstancesIsIdempotent(t *testing.T) {
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
	secondStore, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	client, witnesses := newWitnessedFixture(t, primary, store)
	secondClient, _ := newWitnessedFixture(t, primary, secondStore)
	secondClient.Witnesses = client.Witnesses
	clients := []*WitnessedReplayCheckpointProvider{client, secondClient}
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, provider := range clients {
		provider := provider
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := provider.Consume(context.Background(), request)
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
	scope := witnessScope(checkpointEndpointForConsumer(request))
	for _, witness := range witnesses {
		if commitments := len(witness.historyFor(scope)); commitments != 1 {
			t.Fatalf("independent providers committed witness %s %d times", witness.id, commitments)
		}
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
			store, err := NewFileCheckpointPendingStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := setReplayFileOwner(path); err != nil {
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
	routerMembership := CheckpointEndpoint{DeviceID: string(claims.Router), AccountID: "44444444-4444-4444-8444-444444444444", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 2}
	memberships := checkpointMembershipFixture{string(claims.InitiatingDevice): initiator, string(claims.DestinationDevice): destination, string(claims.Router): routerMembership}
	primary := newDeterministicCheckpointProvider(t)
	primary.register(initiator)
	primary.register(destination)
	primary.register(routerMembership)
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
		witness.revoked[witnessScope(routerMembership)] = routerMembership.RevocationEpoch
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
	routerMembership := CheckpointEndpoint{DeviceID: string(claims.Router), AccountID: "44444444-4444-4444-8444-444444444444", OrganizationID: "33333333-3333-4333-8333-333333333333", RevocationEpoch: 2}
	memberships := checkpointMembershipFixture{string(claims.InitiatingDevice): initiator, string(claims.DestinationDevice): destination, string(claims.Router): routerMembership}
	primary := newDeterministicCheckpointProvider(t)
	primary.register(initiator)
	primary.register(destination)
	primary.register(routerMembership)
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
		witness.revoked[witnessScope(routerMembership)] = routerMembership.RevocationEpoch
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
	updatedRouter := routerMembership
	updatedRouter.RevocationEpoch++
	memberships[string(claims.Router)] = updatedRouter
	now = time.UnixMilli(claims.ExpiresAtUnixMS).Add(time.Second).UTC()
	if err := replay.FinalizeExpiredPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrCheckpointRevoked) {
		t.Fatalf("revoked router historical operation finalized: %v", err)
	}
	memberships[string(claims.Router)] = routerMembership
	updatedInitiator := initiator
	updatedInitiator.RevocationEpoch++
	memberships[string(claims.InitiatingDevice)] = updatedInitiator
	if err := replay.FinalizeExpiredPortForwardAuthorization(context.Background(), authorization); !errors.Is(err, ErrCheckpointRevoked) {
		t.Fatalf("revoked endpoint historical operation finalized: %v", err)
	}
	if len(audit.outcomes) != 0 {
		t.Fatalf("unsupported terminal revocation audit was emitted: %v", audit.outcomes)
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
	store.compactHook = func(context.Context) error {
		return errors.New("injected compaction publication failure")
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
	oversized, err := NewFileCheckpointPendingStore(oversizedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oversizedPath, make([]byte, 129), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setReplayFileOwner(oversizedPath); err != nil {
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
	persisted, err := store.LoadAcknowledgements(context.Background(), request, result.CheckpointReceipt, client.Witnesses)
	if err != nil || committedCheckpointAckCount(persisted) != client.Quorum {
		t.Fatalf("compaction discarded signed terminal evidence: acks=%d err=%v", len(persisted), err)
	}
}

func routedCheckpointRequestForRevocationTest(t *testing.T, primary *deterministicCheckpointProvider) (CheckpointRequest, ed25519.PrivateKey, CheckpointEndpoint) {
	t.Helper()
	request, signer, _, _, _ := makeCheckpointFixture(t, primary,
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222")
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	router := CheckpointEndpoint{
		DeviceID:       identity.DeviceID(publicKey),
		AccountID:      "33333333-3333-4333-8333-333333333333",
		OrganizationID: request.Initiator.OrganizationID,
	}
	request.Router = router
	request.RouteAuthorizationID = "44444444-4444-4444-8444-444444444444"
	request.RouteAuthorizationJTI = "AAAAAAAAAAAAAAAAAAAAAA"
	routeAuthorization, err := json.Marshal(map[string]any{
		"kid": "route-key-v1",
		"claims": map[string]any{
			"jti": request.RouteAuthorizationJTI, "router": router.DeviceID,
			"route": map[string]any{"ID": request.RouteAuthorizationID, "Source": request.Initiator.DeviceID, "Destination": request.Destination.DeviceID},
		},
		"signature": strings.Repeat("A", 86) + "==",
	})
	if err != nil {
		t.Fatal(err)
	}
	request.RouteAuthorizationJSON = string(routeAuthorization)
	request.RouteAuthorizationSHA256 = sha256.Sum256(routeAuthorization)
	request, err = SignCheckpointRequest(signer, request)
	if err != nil {
		t.Fatal(err)
	}
	primary.register(router)
	return request, signer, router
}

func TestWitnessCommitRejectsRevokedInitiatorDestinationAndRouter(t *testing.T) {
	for _, participant := range []string{"initiator", "destination", "router"} {
		t.Run(participant, func(t *testing.T) {
			primary := newDeterministicCheckpointProvider(t)
			request, _, router := routedCheckpointRequestForRevocationTest(t, primary)
			result, err := primary.Consume(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			witness := newDeterministicCheckpointWitness("witness", primary.private.Public().(ed25519.PublicKey))
			var revoked CheckpointEndpoint
			switch participant {
			case "initiator":
				revoked = request.Initiator
			case "destination":
				revoked = request.Destination
			default:
				revoked = router
			}
			if _, err := witness.Revoke(context.Background(), revoked, revoked.RevocationEpoch+1); err != nil {
				t.Fatal(err)
			}
			if _, err := witness.Commit(context.Background(), request, result.CheckpointReceipt); !errors.Is(err, ErrCheckpointRevoked) {
				t.Fatalf("witness committed after %s revocation: %v", participant, err)
			}
		})
	}
}

func TestWitnessAcknowledgeRejectsRevokedInitiatorDestinationAndRouter(t *testing.T) {
	for _, participant := range []string{"initiator", "destination", "router"} {
		t.Run(participant, func(t *testing.T) {
			primary := newDeterministicCheckpointProvider(t)
			request, _, router := routedCheckpointRequestForRevocationTest(t, primary)
			result, err := primary.Consume(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			witness := newDeterministicCheckpointWitness("witness", primary.private.Public().(ed25519.PublicKey))
			if _, err := witness.Commit(context.Background(), request, result.CheckpointReceipt); err != nil {
				t.Fatal(err)
			}
			var revoked CheckpointEndpoint
			switch participant {
			case "initiator":
				revoked = request.Initiator
			case "destination":
				revoked = request.Destination
			default:
				revoked = router
			}
			if _, err := witness.Revoke(context.Background(), revoked, revoked.RevocationEpoch+1); err != nil {
				t.Fatal(err)
			}
			if _, err := witness.Acknowledge(context.Background(), request, result.CheckpointReceipt); !errors.Is(err, ErrCheckpointRevoked) {
				t.Fatalf("witness acknowledged after %s revocation: %v", participant, err)
			}
		})
	}
}

func TestWitnessCommitAndRevocationRaceCannotAcknowledgeAfterRevocation(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, router := routedCheckpointRequestForRevocationTest(t, primary)
	result, err := primary.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	witness := newDeterministicCheckpointWitness("witness", primary.private.Public().(ed25519.PublicKey))
	start := make(chan struct{})
	commitResult := make(chan error, 1)
	revokeResult := make(chan error, 1)
	go func() {
		<-start
		_, err := witness.Commit(context.Background(), request, result.CheckpointReceipt)
		commitResult <- err
	}()
	go func() {
		<-start
		_, err := witness.Revoke(context.Background(), router, router.RevocationEpoch+1)
		revokeResult <- err
	}()
	close(start)
	commitErr := <-commitResult
	revokeErr := <-revokeResult
	if revokeErr != nil {
		t.Fatalf("router revocation failed: %v", revokeErr)
	}
	if commitErr != nil && !errors.Is(commitErr, ErrCheckpointRevoked) {
		t.Fatalf("unexpected concurrent commit result: %v", commitErr)
	}
	if _, err := witness.Acknowledge(context.Background(), request, result.CheckpointReceipt); !errors.Is(err, ErrCheckpointRevoked) {
		t.Fatalf("authorization acknowledged after successful router revocation: %v", err)
	}
}

func TestWitnessAcknowledgeAndRevocationRaceFencesLaterAcknowledgement(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, router := routedCheckpointRequestForRevocationTest(t, primary)
	result, err := primary.Consume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	witness := newDeterministicCheckpointWitness("witness", primary.private.Public().(ed25519.PublicKey))
	if _, err := witness.Commit(context.Background(), request, result.CheckpointReceipt); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	ackResult := make(chan error, 1)
	revokeResult := make(chan error, 1)
	go func() {
		<-start
		_, err := witness.Acknowledge(context.Background(), request, result.CheckpointReceipt)
		ackResult <- err
	}()
	go func() {
		<-start
		_, err := witness.Revoke(context.Background(), router, router.RevocationEpoch+1)
		revokeResult <- err
	}()
	close(start)
	ackErr := <-ackResult
	if ackErr != nil && !errors.Is(ackErr, ErrCheckpointRevoked) {
		t.Fatalf("unexpected concurrent acknowledgement result: %v", ackErr)
	}
	if err := <-revokeResult; err != nil {
		t.Fatalf("router revocation failed: %v", err)
	}
	if _, err := witness.Acknowledge(context.Background(), request, result.CheckpointReceipt); !errors.Is(err, ErrCheckpointRevoked) {
		t.Fatalf("acknowledgement remained eligible after successful revocation: %v", err)
	}
}

func TestWitnessConsumeAndRevocationRaceCannotCommitAfterRevocation(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, router := routedCheckpointRequestForRevocationTest(t, primary)
	witness := newDeterministicCheckpointWitness("witness", primary.private.Public().(ed25519.PublicKey))
	start := make(chan struct{})
	consumeResult := make(chan CheckpointResult, 1)
	consumeErr := make(chan error, 1)
	revokeResult := make(chan error, 1)
	go func() {
		<-start
		result, err := primary.Consume(context.Background(), request)
		consumeResult <- result
		consumeErr <- err
	}()
	go func() {
		<-start
		_, err := witness.Revoke(context.Background(), router, router.RevocationEpoch+1)
		revokeResult <- err
	}()
	close(start)
	result := <-consumeResult
	if err := <-consumeErr; err != nil {
		t.Fatalf("primary consume failed unexpectedly: %v", err)
	}
	if err := <-revokeResult; err != nil {
		t.Fatalf("router revocation failed: %v", err)
	}
	if _, err := witness.Commit(context.Background(), request, result.CheckpointReceipt); !errors.Is(err, ErrCheckpointRevoked) {
		t.Fatalf("primary consumption escaped router revocation fence: %v", err)
	}
}

func TestPersistedAcknowledgementsCannotBypassLaterMembershipRevocation(t *testing.T) {
	for _, participant := range []string{"initiator", "destination", "router"} {
		t.Run(participant, func(t *testing.T) {
			primary := newDeterministicCheckpointProvider(t)
			pending := NewMemoryCheckpointPendingStore()
			client, _ := newWitnessedFixture(t, primary, pending)
			request, _, router := routedCheckpointRequestForRevocationTest(t, primary)
			primary.register(router)
			if err := client.ValidateConfiguration(); err != nil {
				t.Fatal(err)
			}
			if existing, err := pending.Begin(context.Background(), request); err != nil || existing {
				t.Fatalf("pending begin existing=%t err=%v", existing, err)
			}
			result, err := primary.Consume(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := pending.Resolve(context.Background(), request, result.CheckpointReceipt); err != nil {
				t.Fatal(err)
			}
			for _, trust := range client.Witnesses {
				if _, err := trust.Witness.Commit(context.Background(), request, result.CheckpointReceipt); err != nil {
					t.Fatal(err)
				}
				ack, err := trust.Witness.Acknowledge(context.Background(), request, result.CheckpointReceipt)
				if err != nil {
					t.Fatal(err)
				}
				if err := pending.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, ack, trust); err != nil {
					t.Fatal(err)
				}
			}
			var revoked CheckpointEndpoint
			switch participant {
			case "initiator":
				revoked = request.Initiator
			case "destination":
				revoked = request.Destination
			default:
				revoked = router
			}
			if err := client.Revoke(context.Background(), revoked, revoked.RevocationEpoch+1); err != nil {
				t.Fatal(err)
			}
			if _, err := client.acknowledgeWitnessQuorum(context.Background(), request, result.CheckpointReceipt, pending); !errors.Is(err, ErrCheckpointRevoked) {
				t.Fatalf("persisted acknowledgements bypassed %s revocation: %v", participant, err)
			}
		})
	}
}

// TestWitnessAcknowledgementEquivocationCannotReplaceOrContributeEvidence
// checks signed conflicts from one configured witness across retries.
func TestWitnessAcknowledgementEquivocationCannotReplaceOrContributeEvidence(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, signer, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	store := NewMemoryCheckpointPendingStore()
	client, witnesses := newWitnessedFixture(t, primary, store)
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
	for _, trust := range client.Witnesses {
		if _, err := trust.Witness.Commit(context.Background(), request, result.CheckpointReceipt); err != nil {
			t.Fatal(err)
		}
	}
	first, err := witnesses[0].Acknowledge(context.Background(), request, result.CheckpointReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, first, client.Witnesses[0]); err != nil {
		t.Fatal(err)
	}

	conflictingStatus := first
	conflictingStatus.Status = "already_acknowledged"
	if !bytes.Equal(conflictingStatus.Signature, first.Signature) ||
		VerifyCheckpointWitnessAck(conflictingStatus, witnesses[0].id, client.Witnesses[0].PublicKey) != nil {
		t.Fatal("retry metadata changed the signed terminal decision")
	}
	if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, conflictingStatus, client.Witnesses[0]); err != nil {
		t.Fatalf("idempotent successful acknowledgement retry rejected: %v", err)
	}

	// Negative terminal decisions are valid signed evidence. Contradicting an
	// earlier committed vote must durably equivocate rather than be discarded.
	negative := first
	negative.Decision = "revoked"
	negative.Signature = ed25519.Sign(witnesses[0].private, checkpointWitnessAckMessage(negative))
	if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, negative, client.Witnesses[0]); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("contradictory negative decision did not terminally equivocate: %v", err)
	}

	// Wrong-operation responses remain invalid and cannot add evidence.
	conflictingJTI := first
	conflictingJTI.JTI = "CCCCCCCCCCCCCCCCCCCCCC"
	conflictingJTI.Signature = ed25519.Sign(witnesses[0].private, checkpointWitnessAckMessage(conflictingJTI))
	if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, conflictingJTI, client.Witnesses[0]); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("acknowledgement for conflicting operation ID accepted: %v", err)
	}

	conflictingFingerprint := first
	conflictingFingerprint.RequestSHA256[0] ^= 0x80
	conflictingFingerprint.Signature = ed25519.Sign(witnesses[0].private, checkpointWitnessAckMessage(conflictingFingerprint))
	if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, conflictingFingerprint, client.Witnesses[0]); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("acknowledgement for conflicting request fingerprint accepted: %v", err)
	}

	conflictingVector := cloneCheckpointRequest(request)
	conflictingVector.Destination.AccountID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	conflictingVector, err = SignCheckpointRequest(signer, conflictingVector)
	if err != nil {
		t.Fatal(err)
	}
	conflictingVectorAck := first
	conflictingVectorAck.RequestSHA256, err = CheckpointRequestFingerprint(conflictingVector)
	if err != nil {
		t.Fatal(err)
	}
	conflictingVectorAck.Signature = ed25519.Sign(witnesses[0].private, checkpointWitnessAckMessage(conflictingVectorAck))
	if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, conflictingVectorAck, client.Witnesses[0]); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("acknowledgement for conflicting participant vector accepted: %v", err)
	}

	second, err := witnesses[1].Acknowledge(context.Background(), request, result.CheckpointReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, second, client.Witnesses[1]); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("terminally equivocated operation accepted another witness vote: %v", err)
	}
	evidence, err := store.LoadEquivocations(context.Background(), request, result.CheckpointReceipt, client.Witnesses)
	if err != nil || len(evidence) != 1 ||
		!sameCheckpointWitnessAck(evidence[0].Original, first) ||
		!sameCheckpointWitnessAck(evidence[0].Conflicting, negative) {
		t.Fatalf("equivocation evidence did not preserve both signed decisions: evidence=%+v err=%v", evidence, err)
	}
	if _, err := client.acknowledgeWitnessQuorum(context.Background(), request, result.CheckpointReceipt, store); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("terminally equivocated operation recovered a quorum: %v", err)
	}
}

type fixedCheckpointAckWitness struct {
	CheckpointWitness
	ack CheckpointWitnessAck
}

func (w fixedCheckpointAckWitness) Acknowledge(context.Context, CheckpointRequest, CheckpointReceipt) (CheckpointWitnessAck, error) {
	return w.ack, nil
}

type unavailableAckResponse struct {
	CheckpointWitness
}

func (w unavailableAckResponse) Acknowledge(context.Context, CheckpointRequest, CheckpointReceipt) (CheckpointWitnessAck, error) {
	return CheckpointWitnessAck{}, ErrCheckpointUnavailable
}

type unavailableWitness struct {
	CheckpointWitness
}

func (w unavailableWitness) Acknowledge(context.Context, CheckpointRequest, CheckpointReceipt) (CheckpointWitnessAck, error) {
	return CheckpointWitnessAck{}, ErrCheckpointUnavailable
}

func (w unavailableWitness) Head(context.Context, CheckpointWitnessScope) (CheckpointWitnessHead, error) {
	return CheckpointWitnessHead{}, ErrCheckpointUnavailable
}

func preparePersistedWitnessQuorum(t *testing.T, store CheckpointPendingStore) (*WitnessedReplayCheckpointProvider, []*deterministicCheckpointWitness, CheckpointRequest, CheckpointReceipt, []CheckpointWitnessAck) {
	t.Helper()
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
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
	for _, witness := range witnesses {
		if _, err := witness.Commit(context.Background(), request, result.CheckpointReceipt); err != nil {
			t.Fatal(err)
		}
	}
	acks := make([]CheckpointWitnessAck, client.Quorum)
	for i := range acks {
		acks[i], err = witnesses[i].Acknowledge(context.Background(), request, result.CheckpointReceipt)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.(checkpointPendingAcknowledgements).RecordAcknowledgement(context.Background(), request, result.CheckpointReceipt, acks[i], client.Witnesses[i]); err != nil {
			t.Fatal(err)
		}
	}
	return client, witnesses, request, result.CheckpointReceipt, acks
}

func prepareResolvedWitnessOperation(t *testing.T, store CheckpointPendingStore) (*WitnessedReplayCheckpointProvider, []*deterministicCheckpointWitness, CheckpointRequest, CheckpointReceipt) {
	t.Helper()
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
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
	for _, witness := range witnesses {
		if _, err := witness.Commit(context.Background(), request, result.CheckpointReceipt); err != nil {
			t.Fatal(err)
		}
	}
	return client, witnesses, request, result.CheckpointReceipt
}

type compactFailOncePendingStore struct {
	*FileCheckpointPendingStore
	fail bool
}

func (s *compactFailOncePendingStore) Compact(ctx context.Context, acks []CheckpointWitnessAck, witnesses []CheckpointWitnessTrust, quorum int) error {
	if s.fail {
		s.fail = false
		return errors.New("injected compaction failure")
	}
	return s.FileCheckpointPendingStore.Compact(ctx, acks, witnesses, quorum)
}

func signedDecision(t *testing.T, witness *deterministicCheckpointWitness, original CheckpointWitnessAck, decision string) CheckpointWitnessAck {
	t.Helper()
	conflict := original
	conflict.Decision = decision
	conflict.Signature = ed25519.Sign(witness.private, checkpointWitnessAckMessage(conflict))
	if err := VerifyCheckpointWitnessAck(conflict, witness.id, witness.private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("test conflict is not a valid signed decision: %v", err)
	}
	return conflict
}

func TestPersistedQuorumDetectsAndPersistsEquivocationAcrossRestart(t *testing.T) {
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
	client, witnesses, request, receipt, original := preparePersistedWitnessQuorum(t, store)
	conflict := signedDecision(t, witnesses[0], original[0], "revoked")
	client.Witnesses[0].Witness = fixedCheckpointAckWitness{CheckpointWitness: witnesses[0], ack: conflict}
	client.Witnesses[1].Witness = unavailableWitness{CheckpointWitness: witnesses[1]}
	client.Witnesses[2].Witness = unavailableWitness{CheckpointWitness: witnesses[2]}

	released := false
	err = client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
		released = true
		return nil
	})
	if !errors.Is(err, ErrCheckpointConflict) || released {
		t.Fatalf("equivocation did not block finalization: err=%v released=%t", err, released)
	}
	if _, err := store.LoadAcknowledgements(context.Background(), request, receipt, client.Witnesses); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("equivocated operation did not become terminal: %v", err)
	}
	if _, err := store.Begin(context.Background(), request); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("terminal operation accepted a new begin: %v", err)
	}
	evidence, err := store.LoadEquivocations(context.Background(), request, receipt, client.Witnesses)
	if err != nil || len(evidence) != 1 {
		t.Fatalf("durable equivocation evidence=%d err=%v", len(evidence), err)
	}
	if !sameCheckpointWitnessAck(evidence[0].Original, original[0]) ||
		!sameCheckpointWitnessAck(evidence[0].Conflicting, conflict) {
		t.Fatal("equivocation evidence does not preserve both signed decisions")
	}
	journalBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var journal checkpointPendingSnapshot
	if err := json.Unmarshal(journalBytes, &journal); err != nil {
		t.Fatal(err)
	}
	entry := journal.Entries[checkpointPendingKey(request)]
	if entry.State != "equivocated" || len(entry.Acknowledgements) != 2 {
		t.Fatalf("terminal journal state=%q original acknowledgements=%d", entry.State, len(entry.Acknowledgements))
	}
	originalFound := false
	for _, ack := range entry.Acknowledgements {
		if ack.WitnessID == original[0].WitnessID && sameCheckpointWitnessAck(ack, original[0]) {
			originalFound = true
		}
	}
	if !originalFound {
		t.Fatal("persisting equivocation replaced or deleted the original acknowledgement")
	}

	restarted, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetCheckpointTrustAnchors(client.PrimaryKey, client.Witnesses, client.Quorum); err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.LoadEquivocations(context.Background(), request, receipt, client.Witnesses)
	if err != nil || len(recovered) != 1 ||
		!sameCheckpointWitnessAck(recovered[0].Original, original[0]) ||
		!sameCheckpointWitnessAck(recovered[0].Conflicting, conflict) {
		t.Fatalf("equivocation evidence did not survive restart: count=%d err=%v", len(recovered), err)
	}
	restartedClient := &WitnessedReplayCheckpointProvider{
		Primary: client.Primary, PrimaryKey: client.PrimaryKey, Witnesses: client.Witnesses,
		Quorum: client.Quorum, Pending: restarted,
	}
	released = false
	if err := restartedClient.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
		released = true
		return nil
	}); !errors.Is(err, ErrCheckpointConflict) || released {
		t.Fatalf("subsequent finalization was not terminally rejected: err=%v released=%t", err, released)
	}
}

func TestPersistedQuorumRecoveryDoesNotRequireWitnessAvailability(t *testing.T) {
	client, witnesses, request, receipt, original := preparePersistedWitnessQuorum(t, NewMemoryCheckpointPendingStore())
	client.Witnesses[0].Witness = unavailableAckResponse{CheckpointWitness: witnesses[0]}
	client.Witnesses[1].Witness = unavailableAckResponse{CheckpointWitness: witnesses[1]}
	witnesses[2].available = false
	called := false
	if err := client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
		called = true
		return nil
	}); err != nil || !called {
		t.Fatalf("cached quorum did not recover during witness outages: err=%v callback=%t", err, called)
	}
	if len(original) != client.Quorum || receipt.RequestSHA256 == ([sha256.Size]byte{}) {
		t.Fatal("test did not prepare an authenticated persisted quorum")
	}
}

func TestInvalidSignedConflictCannotPoisonPersistedQuorum(t *testing.T) {
	client, witnesses, request, receipt, original := preparePersistedWitnessQuorum(t, NewMemoryCheckpointPendingStore())
	invalid := signedDecision(t, witnesses[0], original[0], "revoked")
	invalid.Signature = append([]byte(nil), invalid.Signature...)
	invalid.Signature[0] ^= 0x80
	client.Witnesses[0].Witness = fixedCheckpointAckWitness{CheckpointWitness: witnesses[0], ack: invalid}
	client.Witnesses[1].Witness = unavailableAckResponse{CheckpointWitness: witnesses[1]}
	called := false
	if err := client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
		called = true
		return nil
	}); err != nil || !called {
		t.Fatalf("invalid conflict poisoned valid cached quorum: err=%v callback=%t", err, called)
	}
	evidence, err := client.Pending.(checkpointPendingAcknowledgements).LoadEquivocations(context.Background(), request, receipt, client.Witnesses)
	if err != nil || len(evidence) != 0 {
		t.Fatalf("invalid signed response poisoned equivocation journal: evidence=%+v err=%v", evidence, err)
	}
	persisted, err := client.Pending.(checkpointPendingAcknowledgements).LoadAcknowledgements(context.Background(), request, receipt, client.Witnesses)
	if err != nil || committedCheckpointAckCount(persisted) < client.Quorum {
		t.Fatalf("invalid response damaged original committed quorum: acks=%d err=%v", len(persisted), err)
	}
}

func TestRepeatedEquivocationDetectionIsIdempotentAndTerminal(t *testing.T) {
	client, witnesses, request, receipt, original := preparePersistedWitnessQuorum(t, NewMemoryCheckpointPendingStore())
	conflict := signedDecision(t, witnesses[0], original[0], "aborted")
	client.Witnesses[0].Witness = fixedCheckpointAckWitness{CheckpointWitness: witnesses[0], ack: conflict}
	client.Witnesses[1].Witness = unavailableAckResponse{CheckpointWitness: witnesses[1]}
	for attempt := 0; attempt < 2; attempt++ {
		called := false
		err := client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
			called = true
			return nil
		})
		if !errors.Is(err, ErrCheckpointConflict) || called {
			t.Fatalf("attempt %d equivocation result err=%v callback=%t", attempt, err, called)
		}
	}
	evidence, err := client.Pending.(checkpointPendingAcknowledgements).LoadEquivocations(context.Background(), request, receipt, client.Witnesses)
	if err != nil || len(evidence) != 1 {
		t.Fatalf("repeated conflict duplicated or lost evidence: count=%d err=%v", len(evidence), err)
	}
}

func TestConcurrentFinalizationRunsCallbackAtMostOnce(t *testing.T) {
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
	client, _, request, _, _ := preparePersistedWitnessQuorum(t, store)
	other := &WitnessedReplayCheckpointProvider{
		Primary: client.Primary, PrimaryKey: client.PrimaryKey, Witnesses: client.Witnesses,
		Quorum: client.Quorum, Pending: store,
	}
	var mu sync.Mutex
	callbacks := 0
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	providers := []*WitnessedReplayCheckpointProvider{client, other}
	for i := 0; i < 2; i++ {
		provider := providers[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- provider.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
				mu.Lock()
				callbacks++
				mu.Unlock()
				return nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		} else {
			t.Fatalf("idempotent concurrent finalization failed: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if successes != 2 || callbacks != 1 {
		t.Fatalf("concurrent finalization successes=%d callbacks=%d", successes, callbacks)
	}
}

func TestEquivocationEvidencePersistenceInterruptionFailsClosed(t *testing.T) {
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
	client, witnesses, request, receipt, original := preparePersistedWitnessQuorum(t, store)
	conflict := signedDecision(t, witnesses[0], original[0], "revoked")
	client.Witnesses[0].Witness = fixedCheckpointAckWitness{CheckpointWitness: witnesses[0], ack: conflict}
	client.Witnesses[1].Witness = unavailableAckResponse{CheckpointWitness: witnesses[1]}
	store.writeSnapshot = func(_ string, value any, _ string, _ int64) error {
		if snapshot, ok := value.(checkpointPendingSnapshot); ok {
			for _, entry := range snapshot.Entries {
				if entry.State == "equivocated" {
					return errors.New("injected equivocation publication interruption")
				}
			}
		}
		return writeReplayJSON(store.Path, value, replayStagingPattern(store.Path, "pendingops"), checkpointPendingMaxSize)
	}
	called := false
	err = client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrCheckpointUnavailable) || called {
		t.Fatalf("interrupted evidence persistence did not fail closed: err=%v callback=%t", err, called)
	}
	store.writeSnapshot = nil
	if _, err := store.LoadAcknowledgements(context.Background(), request, receipt, client.Witnesses); err != nil {
		t.Fatalf("failed evidence publication altered original quorum: %v", err)
	}
	if evidence, err := store.LoadEquivocations(context.Background(), request, receipt, client.Witnesses); err != nil || len(evidence) != 0 {
		t.Fatalf("interrupted evidence was partially persisted: count=%d err=%v", len(evidence), err)
	}
	called = false
	if err := client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
		called = true
		return nil
	}); !errors.Is(err, ErrCheckpointConflict) || called {
		t.Fatalf("retry after restored journal writer did not persist terminal conflict: err=%v callback=%t", err, called)
	}
}

func TestEquivocationJournalCorruptionFailsClosed(t *testing.T) {
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
	client, witnesses, request, receipt, original := preparePersistedWitnessQuorum(t, store)
	conflict := signedDecision(t, witnesses[0], original[0], "revoked")
	client.Witnesses[0].Witness = fixedCheckpointAckWitness{CheckpointWitness: witnesses[0], ack: conflict}
	client.Witnesses[1].Witness = unavailableAckResponse{CheckpointWitness: witnesses[1]}
	if err := client.FinalizeWithAudit(context.Background(), request, nil); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("expected persisted equivocation, got %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot checkpointPendingSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	for key, entry := range snapshot.Entries {
		if entry.State != "equivocated" {
			continue
		}
		entry.Equivocations[0].Conflicting.Signature[0] ^= 0x80
		snapshot.Entries[key] = entry
	}
	corrupt, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetCheckpointTrustAnchors(client.PrimaryKey, client.Witnesses, client.Quorum); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.LoadEquivocations(context.Background(), request, receipt, client.Witnesses); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("corrupt equivocation journal was not rejected: %v", err)
	}
}

func TestPersistedQuorumEquivocationRepeatedRecovery(t *testing.T) {
	for attempt := 0; attempt < 10; attempt++ {
		t.Run(fmt.Sprintf("attempt-%02d", attempt), func(t *testing.T) {
			client, witnesses, request, receipt, original := preparePersistedWitnessQuorum(t, NewMemoryCheckpointPendingStore())
			conflict := signedDecision(t, witnesses[0], original[0], "revoked")
			client.Witnesses[0].Witness = fixedCheckpointAckWitness{CheckpointWitness: witnesses[0], ack: conflict}
			client.Witnesses[1].Witness = unavailableAckResponse{CheckpointWitness: witnesses[1]}
			called := false
			err := client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
				called = true
				return nil
			})
			if !errors.Is(err, ErrCheckpointConflict) || called {
				t.Fatalf("attempt %d did not fail closed: err=%v callback=%t", attempt, err, called)
			}
			evidence, err := client.Pending.(checkpointPendingAcknowledgements).LoadEquivocations(context.Background(), request, receipt, client.Witnesses)
			if err != nil || len(evidence) != 1 ||
				!sameCheckpointWitnessAck(evidence[0].Original, original[0]) ||
				!sameCheckpointWitnessAck(evidence[0].Conflicting, conflict) {
				t.Fatalf("attempt %d lost authenticated equivocation evidence: count=%d err=%v", attempt, len(evidence), err)
			}
		})
	}
}

func TestNegativeFirstTerminalDecisionsAreDurableAndEquivocationTerminal(t *testing.T) {
	for _, backend := range []string{"memory", "file"} {
		for _, decision := range []string{"revoked", "aborted"} {
			t.Run(backend+"/"+decision, func(t *testing.T) {
				var store CheckpointPendingStore
				var path string
				if backend == "memory" {
					store = NewMemoryCheckpointPendingStore()
				} else {
					dir := t.TempDir()
					if err := os.Chmod(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := setReplayTestDirectoryOwner(dir); err != nil {
						t.Fatal(err)
					}
					path = filepath.Join(dir, "pending.json")
					var err error
					store, err = NewFileCheckpointPendingStore(path)
					if err != nil {
						t.Fatal(err)
					}
				}
				client, witnesses, request, receipt := prepareResolvedWitnessOperation(t, store)
				committed, err := witnesses[0].Acknowledge(context.Background(), request, receipt)
				if err != nil {
					t.Fatal(err)
				}
				negative := signedDecision(t, witnesses[0], committed, decision)
				acks := store.(checkpointPendingAcknowledgements)
				if err := acks.RecordAcknowledgement(context.Background(), request, receipt, negative, client.Witnesses[0]); err != nil {
					t.Fatalf("persist first-seen %s decision: %v", decision, err)
				}
				if err := acks.RecordAcknowledgement(context.Background(), request, receipt, negative, client.Witnesses[0]); err != nil {
					t.Fatalf("identical negative retry was not idempotent: %v", err)
				}

				if backend == "file" {
					restarted, err := NewFileCheckpointPendingStore(path)
					if err != nil {
						t.Fatal(err)
					}
					if err := restarted.SetCheckpointTrustAnchors(client.PrimaryKey, client.Witnesses, client.Quorum); err != nil {
						t.Fatal(err)
					}
					store = restarted
					client.Pending = restarted
					acks = restarted
				}
				persisted, err := acks.LoadAcknowledgements(context.Background(), request, receipt, client.Witnesses)
				if err != nil || len(persisted) != 1 || persisted[0].Decision != decision {
					t.Fatalf("negative decision did not survive storage/restart: acks=%+v err=%v", persisted, err)
				}

				callbackCalled := false
				err = client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
					callbackCalled = true
					return nil
				})
				if !errors.Is(err, ErrCheckpointConflict) || callbackCalled {
					t.Fatalf("negative-first contradiction did not fail closed: err=%v callback=%t", err, callbackCalled)
				}
				evidence, err := acks.LoadEquivocations(context.Background(), request, receipt, client.Witnesses)
				if err != nil || len(evidence) != 1 ||
					evidence[0].Original.Decision != decision ||
					evidence[0].Conflicting.Decision != "committed" {
					t.Fatalf("negative-first equivocation evidence missing: evidence=%+v err=%v", evidence, err)
				}
				var entry checkpointPendingEntry
				if backend == "memory" {
					entry = store.(*MemoryCheckpointPendingStore).entries[checkpointPendingKey(request)]
				} else {
					raw, readErr := os.ReadFile(path)
					if readErr != nil {
						t.Fatal(readErr)
					}
					var snapshot checkpointPendingSnapshot
					if err := json.Unmarshal(raw, &snapshot); err != nil {
						t.Fatal(err)
					}
					entry = snapshot.Entries[checkpointPendingKey(request)]
				}
				if len(entry.Acknowledgements) != 3 || committedCheckpointAckCount(entry.Acknowledgements) != 2 {
					t.Fatalf("first-seen decisions from other witnesses were lost: %+v", entry.Acknowledgements)
				}
			})
		}
	}
}

func TestWrongOperationSignedAcknowledgementCannotPoisonJournal(t *testing.T) {
	store := NewMemoryCheckpointPendingStore()
	client, witnesses, request, receipt := prepareResolvedWitnessOperation(t, store)
	ack, err := witnesses[0].Acknowledge(context.Background(), request, receipt)
	if err != nil {
		t.Fatal(err)
	}
	ack.JTI = "99999999-9999-4999-8999-999999999999"
	ack.Signature = ed25519.Sign(witnesses[0].private, checkpointWitnessAckMessage(ack))
	if err := store.RecordAcknowledgement(context.Background(), request, receipt, ack, client.Witnesses[0]); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("wrong-operation signed acknowledgement accepted: %v", err)
	}
	persisted, err := store.LoadAcknowledgements(context.Background(), request, receipt, client.Witnesses)
	if err != nil || len(persisted) != 0 {
		t.Fatalf("wrong-operation response poisoned journal: acks=%+v err=%v", persisted, err)
	}
}

func TestVersionTwoPendingJournalIsRejectedWithoutChangingOriginalBytes(t *testing.T) {
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
	original := []byte("{\"version\":2,\"entries\":{}}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setReplayFileOwner(path); err != nil {
		t.Fatal(err)
	}
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	if _, err := store.Begin(context.Background(), request); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("v2 journal was not rejected: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("rejected v2 journal bytes were modified or discarded")
	}
}

func TestConcurrentEquivocationPublicationPrecedesFinalizationCallback(t *testing.T) {
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
	client, witnesses, request, receipt, original := preparePersistedWitnessQuorum(t, store)
	conflict := signedDecision(t, witnesses[0], original[0], "revoked")
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	store.writeSnapshot = func(path string, value any, pattern string, maxSize int64) error {
		once.Do(func() {
			close(entered)
			<-release
		})
		return writeReplayJSON(path, value, pattern, maxSize)
	}
	equivocationDone := make(chan error, 1)
	go func() {
		equivocationDone <- store.RecordEquivocation(context.Background(), request, receipt, original[0], conflict, client.Witnesses[0])
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("equivocation did not reach durable publication")
	}

	callbackCalled := make(chan struct{}, 1)
	finalizationDone := make(chan error, 1)
	go func() {
		finalizationDone <- client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
			callbackCalled <- struct{}{}
			return nil
		})
	}()
	close(release)
	if err := <-equivocationDone; err != nil {
		t.Fatalf("equivocation publication failed: %v", err)
	}
	if err := <-finalizationDone; !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("finalization did not observe committed equivocation: %v", err)
	}
	select {
	case <-callbackCalled:
		t.Fatal("completion callback ran after equivocation committed")
	default:
	}
}

func TestFinalizationCallbackIsIdempotentAcrossCompactionFailureAndRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	base, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &compactFailOncePendingStore{FileCheckpointPendingStore: base, fail: true}
	client, witnesses, request, _, _ := preparePersistedWitnessQuorum(t, wrapped)

	primary := client.Primary.(*deterministicCheckpointProvider)
	var mu sync.Mutex
	var firstEvidence *CheckpointFinalizationEvidence
	callbackCount := 0
	effects := make(map[string]bool)
	effectCount := 0
	sink := func(_ context.Context, operationID string, evidence CheckpointFinalizationEvidence) error {
		mu.Lock()
		defer mu.Unlock()
		callbackCount++
		if firstEvidence == nil {
			copy, err := cloneCheckpointFinalizationEvidence(evidence)
			if err != nil {
				return err
			}
			firstEvidence = &copy
		} else if !reflect.DeepEqual(*firstEvidence, evidence) {
			return errors.New("retry changed persisted finalization evidence")
		}
		if !effects[operationID] {
			effects[operationID] = true
			effectCount++
		}
		return nil
	}
	if err := client.FinalizeWithAudit(context.Background(), request, sink); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatalf("injected compaction failure did not surface: %v", err)
	}
	mu.Lock()
	if effectCount != 1 {
		mu.Unlock()
		t.Fatalf("first completion effects=%d, want 1", effectCount)
	}
	if firstEvidence == nil || callbackCount != 1 {
		mu.Unlock()
		t.Fatalf("first proof bundle was not submitted exactly once: evidence=%t callbacks=%d", firstEvidence != nil, callbackCount)
	}
	mu.Unlock()

	restarted, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restartedClient := &WitnessedReplayCheckpointProvider{
		Primary: client.Primary, PrimaryKey: client.PrimaryKey, Witnesses: client.Witnesses,
		Quorum: client.Quorum, Pending: restarted,
	}
	if err := restartedClient.ValidateConfiguration(); err != nil {
		t.Fatal(err)
	}
	if err := restartedClient.FinalizeWithAudit(context.Background(), request, sink); err != nil {
		t.Fatalf("retry after restart did not complete: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if effectCount != 1 {
		t.Fatalf("externally visible completion effect repeated: %d", effectCount)
	}
	if callbackCount != 1 {
		t.Fatalf("completed audit callback repeated after compaction retry: callbacks=%d", callbackCount)
	}
	operationID, err := checkpointFinalizationID(request, func() CheckpointReceipt {
		consumer, _ := checkpointConsumer(request)
		ledgerKey := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
		primary.mu.Lock()
		defer primary.mu.Unlock()
		return cloneCheckpointReceiptValue(primary.ledgers[ledgerKey].used[request.JTI].receipt)
	}())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := restarted.LoadFinalizationComplete(context.Background(), request, func() CheckpointReceipt {
		consumer, _ := checkpointConsumer(request)
		ledgerKey := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
		primary.mu.Lock()
		defer primary.mu.Unlock()
		return cloneCheckpointReceiptValue(primary.ledgers[ledgerKey].used[request.JTI].receipt)
	}(), operationID)
	if err != nil || !completed {
		t.Fatalf("durable completion marker missing: completed=%t err=%v", completed, err)
	}
	_ = witnesses
}

func TestNegativeTerminalDecisionNeverContributesToQuorum(t *testing.T) {
	store := NewMemoryCheckpointPendingStore()
	client, witnesses, request, receipt := prepareResolvedWitnessOperation(t, store)
	committed, err := witnesses[2].Acknowledge(context.Background(), request, receipt)
	if err != nil {
		t.Fatal(err)
	}
	negative := signedDecision(t, witnesses[2], committed, "revoked")
	if err := store.RecordAcknowledgement(context.Background(), request, receipt, negative, client.Witnesses[2]); err != nil {
		t.Fatal(err)
	}
	client.Witnesses[0].Witness = unavailableAckResponse{CheckpointWitness: witnesses[0]}
	client.Witnesses[1].Witness = unavailableAckResponse{CheckpointWitness: witnesses[1]}
	client.Witnesses[2].Witness = fixedCheckpointAckWitness{CheckpointWitness: witnesses[2], ack: negative}
	called := false
	err = client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrCheckpointQuorum) || called {
		t.Fatalf("negative vote contributed to quorum: err=%v callback=%t", err, called)
	}
	persisted, err := store.LoadAcknowledgements(context.Background(), request, receipt, client.Witnesses)
	if err != nil || len(persisted) != 1 || committedCheckpointAckCount(persisted) != 0 {
		t.Fatalf("negative vote journal state=%+v err=%v", persisted, err)
	}
}

func TestFirstSeenNegativeDecisionPersistsBesideCommittedQuorum(t *testing.T) {
	store := NewMemoryCheckpointPendingStore()
	client, witnesses, request, receipt := prepareResolvedWitnessOperation(t, store)
	committed, err := witnesses[0].Acknowledge(context.Background(), request, receipt)
	if err != nil {
		t.Fatal(err)
	}
	negative := signedDecision(t, witnesses[0], committed, "aborted")
	client.Witnesses[0].Witness = fixedCheckpointAckWitness{CheckpointWitness: witnesses[0], ack: negative}
	callbackCalled := false
	if err := client.FinalizeWithAudit(context.Background(), request, func(context.Context, string, CheckpointFinalizationEvidence) error {
		callbackCalled = true
		return nil
	}); err != nil {
		t.Fatalf("two committed votes did not satisfy quorum: %v", err)
	}
	if !callbackCalled {
		t.Fatal("committed quorum did not execute completion callback")
	}
	persisted, err := store.LoadAcknowledgements(context.Background(), request, receipt, client.Witnesses)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 3 || committedCheckpointAckCount(persisted) != client.Quorum {
		t.Fatalf("persisted terminal decisions=%+v", persisted)
	}
	negativeCount := 0
	for _, ack := range persisted {
		if ack.Decision == "aborted" {
			negativeCount++
		}
	}
	if negativeCount != 1 {
		t.Fatalf("first-seen negative decision count=%d, want 1", negativeCount)
	}
}

type transitionBlockingCheckpointPrimary struct {
	ReplayCheckpointProvider
	headEntered   chan struct{}
	releaseHead   chan struct{}
	revokeEntered chan struct{}
	releaseRevoke chan struct{}
	headOnce      sync.Once
	revokeOnce    sync.Once
}

func (p *transitionBlockingCheckpointPrimary) Head(ctx context.Context, endpoint CheckpointEndpoint) (CheckpointHead, error) {
	if p.headEntered != nil {
		p.headOnce.Do(func() { close(p.headEntered) })
		select {
		case <-p.releaseHead:
		case <-ctx.Done():
			return CheckpointHead{}, ctx.Err()
		}
	}
	return p.ReplayCheckpointProvider.Head(ctx, endpoint)
}

func (p *transitionBlockingCheckpointPrimary) Revoke(ctx context.Context, endpoint CheckpointEndpoint, next uint64) error {
	if p.revokeEntered != nil {
		p.revokeOnce.Do(func() { close(p.revokeEntered) })
		select {
		case <-p.releaseRevoke:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return p.ReplayCheckpointProvider.Revoke(ctx, endpoint, next)
}

func newTransitionTestStore(t *testing.T, fileBacked bool) CheckpointPendingStore {
	t.Helper()
	if !fileBacked {
		return NewMemoryCheckpointPendingStore()
	}
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
	return store
}

func setTransitionWaitHook(store CheckpointPendingStore, wait chan<- struct{}) {
	hook := func() {
		select {
		case wait <- struct{}{}:
		default:
		}
	}
	switch value := store.(type) {
	case *MemoryCheckpointPendingStore:
		value.transitionWait = hook
	case *FileCheckpointPendingStore:
		value.transitionWait = hook
	}
}

func waitForTestSignal(t *testing.T, ctx context.Context, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s: %v", name, ctx.Err())
	}
}

func waitForTestResult(t *testing.T, ctx context.Context, result <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s: %v", name, ctx.Err())
		return ctx.Err()
	}
}

func TestRevokeAndFinalizeShareTransitionLock(t *testing.T) {
	for _, fileBacked := range []bool{false, true} {
		storeName := "memory"
		if fileBacked {
			storeName = "file"
		}
		for _, revokeFirst := range []bool{false, true} {
			orderName := "finalize-first"
			if revokeFirst {
				orderName = "revoke-first"
			}
			t.Run(storeName+"/"+orderName, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				primary := newDeterministicCheckpointProvider(t)
				request, _, _, _, _ := makeCheckpointFixture(t, primary,
					"11111111-1111-4111-8111-111111111111",
					"22222222-2222-4222-8222-222222222222")
				store := newTransitionTestStore(t, fileBacked)
				client, _ := newWitnessedFixture(t, primary, store)
				if _, err := client.Consume(ctx, request); err != nil {
					t.Fatal(err)
				}

				contention := make(chan struct{}, 1)
				setTransitionWaitHook(store, contention)
				callback := make(chan string, 1)
				callbackSignal := make(chan struct{}, 1)
				finalizeDone := make(chan error, 1)
				revokeDone := make(chan error, 1)
				callbackFn := func(_ context.Context, operationID string, _ CheckpointFinalizationEvidence) error {
					callback <- operationID
					callbackSignal <- struct{}{}
					return nil
				}

				if revokeFirst {
					blocking := &transitionBlockingCheckpointPrimary{
						ReplayCheckpointProvider: primary,
						revokeEntered:            make(chan struct{}),
						releaseRevoke:            make(chan struct{}),
					}
					var releaseOnce sync.Once
					release := func() { releaseOnce.Do(func() { close(blocking.releaseRevoke) }) }
					t.Cleanup(release)
					client.Primary = blocking
					go func() {
						revokeDone <- client.Revoke(ctx, request.Initiator, request.Initiator.RevocationEpoch+1)
					}()
					waitForTestSignal(t, ctx, blocking.revokeEntered, "primary revocation entry")
					go func() {
						finalizeDone <- client.FinalizeWithAudit(ctx, request, callbackFn)
					}()
					waitForTestSignal(t, ctx, contention, "finalization lock contention")
					select {
					case <-callbackSignal:
						t.Fatal("audit callback ran while revocation held the transition lock")
					default:
					}
					release()
					if err := waitForTestResult(t, ctx, revokeDone, "revocation"); err != nil {
						t.Fatalf("revoke-first failed: %v", err)
					}
					if err := waitForTestResult(t, ctx, finalizeDone, "finalization"); err == nil {
						t.Fatal("finalization succeeded after revocation won the lock")
					}
					select {
					case id := <-callback:
						t.Fatalf("audit callback ran after revocation: %s", id)
					default:
					}
					return
				}

				blocking := &transitionBlockingCheckpointPrimary{
					ReplayCheckpointProvider: primary,
					headEntered:              make(chan struct{}),
					releaseHead:              make(chan struct{}),
					revokeEntered:            make(chan struct{}),
					releaseRevoke:            make(chan struct{}),
				}
				var releaseHeadOnce, releaseRevokeOnce sync.Once
				releaseHead := func() { releaseHeadOnce.Do(func() { close(blocking.releaseHead) }) }
				releaseRevoke := func() { releaseRevokeOnce.Do(func() { close(blocking.releaseRevoke) }) }
				t.Cleanup(func() {
					releaseHead()
					releaseRevoke()
				})
				client.Primary = blocking
				go func() {
					finalizeDone <- client.FinalizeWithAudit(ctx, request, callbackFn)
				}()
				waitForTestSignal(t, ctx, blocking.headEntered, "primary head entry")
				go func() {
					revokeDone <- client.Revoke(ctx, request.Initiator, request.Initiator.RevocationEpoch+1)
				}()
				waitForTestSignal(t, ctx, contention, "revocation lock contention")
				select {
				case <-blocking.revokeEntered:
					t.Fatal("primary revocation crossed the transition lock before finalization")
				default:
				}
				releaseHead()
				if err := waitForTestResult(t, ctx, finalizeDone, "finalization"); err != nil {
					t.Fatalf("finalize-first failed: %v", err)
				}
				select {
				case id := <-callback:
					if id == "" {
						t.Fatal("finalization callback received empty operation ID")
					}
				default:
					t.Fatal("finalization completed without audit callback")
				}
				waitForTestSignal(t, ctx, blocking.revokeEntered, "primary revocation after finalization")
				releaseRevoke()
				if err := waitForTestResult(t, ctx, revokeDone, "revocation"); err != nil {
					t.Fatalf("revoke after finalization failed: %v", err)
				}
			})
		}
	}
}

type fileCheckpointAuditRecord struct {
	OperationID string `json:"operation_id"`
	Outcome     string `json:"outcome"`
}

type fileCheckpointAuditFixture struct {
	path  string
	calls int
}

func (a *fileCheckpointAuditFixture) RecordCheckpointFinalization(ctx context.Context, _ CheckpointRequest, operationID, outcome string, _ *CheckpointFinalizationEvidence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if operationID == "" || outcome == "" {
		return ErrCheckpointIntegrity
	}
	a.calls++
	var records []fileCheckpointAuditRecord
	data, err := os.ReadFile(a.path)
	if err == nil {
		if err := json.Unmarshal(data, &records); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, record := range records {
		if record.OperationID == operationID && record.Outcome == outcome {
			return nil
		}
	}
	records = append(records, fileCheckpointAuditRecord{OperationID: operationID, Outcome: outcome})
	return writeReplayJSON(a.path, records, replayStagingPattern(a.path, "audit"), 1<<20)
}

func TestFinalizationAuditSinkDeduplicatesAfterCompletionMarkerFailureAndRestart(t *testing.T) {
	primary := newDeterministicCheckpointProvider(t)
	request, _, _, _, _ := makeCheckpointFixture(t, primary,
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReplayTestDirectoryOwner(dir); err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(dir, "pending.json")
	store, err := NewFileCheckpointPendingStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := newWitnessedFixture(t, primary, store)
	if _, err := client.Consume(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	sink := &fileCheckpointAuditFixture{path: filepath.Join(dir, "audit.json")}
	failCompletionMarker := true
	store.writeSnapshot = func(path string, value any, pattern string, maxSize int64) error {
		snapshot, ok := value.(checkpointPendingSnapshot)
		if !ok {
			return errors.New("unexpected pending snapshot type")
		}
		if failCompletionMarker {
			for _, entry := range snapshot.Entries {
				if entry.FinalizationComplete {
					failCompletionMarker = false
					return errors.New("injected completion-marker persistence failure")
				}
			}
		}
		return writeReplayJSON(path, value, pattern, maxSize)
	}
	var firstEvidence *CheckpointFinalizationEvidence
	callbackCount := 0
	invoke := func(provider *WitnessedReplayCheckpointProvider) (string, error) {
		var operationID string
		err := provider.FinalizeWithAudit(context.Background(), request, func(ctx context.Context, id string, evidence CheckpointFinalizationEvidence) error {
			operationID = id
			callbackCount++
			if firstEvidence == nil {
				copy, err := cloneCheckpointFinalizationEvidence(evidence)
				if err != nil {
					return err
				}
				firstEvidence = &copy
			} else if !reflect.DeepEqual(*firstEvidence, evidence) {
				return errors.New("retry changed persisted finalization evidence")
			}
			return sink.RecordCheckpointFinalization(ctx, request, id, CheckpointFinalizationComplete, nil)
		})
		return operationID, err
	}
	firstID, err := invoke(client)
	if err == nil || firstID == "" || sink.calls != 1 || callbackCount != 1 || firstEvidence == nil {
		t.Fatalf("first finalization did not hit injected marker failure: id=%q calls=%d callbacks=%d evidence=%t err=%v", firstID, sink.calls, callbackCount, firstEvidence != nil, err)
	}
	// The first sink call may have committed even though the client observed an
	// error while persisting its completion marker. Advance provider heads before
	// retry; the persisted evidence must remain byte-for-byte identical.
	if err := client.Revoke(context.Background(), request.Initiator, request.Initiator.RevocationEpoch+1); err != nil {
		t.Fatalf("revoke after ambiguous audit result: %v", err)
	}

	restartedStore, err := NewFileCheckpointPendingStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := newWitnessedFixture(t, primary, restartedStore)
	restarted.Witnesses = client.Witnesses
	secondID, err := invoke(restarted)
	if err != nil {
		t.Fatalf("finalization retry after restart failed: %v", err)
	}
	if secondID != firstID || sink.calls != 2 || callbackCount != 2 {
		t.Fatalf("retry changed operation identity or skipped exact evidence retry: first=%q second=%q calls=%d callbacks=%d", firstID, secondID, sink.calls, callbackCount)
	}
	data, err := os.ReadFile(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	var records []fileCheckpointAuditRecord
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].OperationID != firstID || records[0].Outcome != CheckpointFinalizationComplete {
		t.Fatalf("durable audit sink did not deduplicate the retry: %+v", records)
	}
	completed, err := restartedStore.LoadFinalizationComplete(context.Background(), request, func() CheckpointReceipt {
		_, receipt, found, hasReceipt, loadErr := restartedStore.LoadFinalization(context.Background(), request.ConsumingDeviceID, request.JTI, request.AuthorizationSHA256)
		if loadErr != nil || !found || !hasReceipt {
			t.Fatalf("load finalized receipt: found=%t receipt=%t err=%v", found, hasReceipt, loadErr)
		}
		return receipt
	}(), firstID)
	if err != nil || !completed {
		t.Fatalf("completion marker not persisted on retry: completed=%t err=%v", completed, err)
	}
}

func TestCheckpointTransitionLockCancellation(t *testing.T) {
	for _, fileBacked := range []bool{false, true} {
		name := "memory"
		if fileBacked {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			store := newTransitionTestStore(t, fileBacked)
			unlock, err := store.(checkpointPendingTransitionLocker).LockTransition(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := unlock(); err != nil {
					t.Errorf("release transition lock: %v", err)
				}
			}()
			contention := make(chan struct{}, 1)
			setTransitionWaitHook(store, contention)
			waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer waitCancel()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				_, err := store.(checkpointPendingTransitionLocker).LockTransition(ctx)
				done <- err
			}()
			waitForTestSignal(t, waitCtx, contention, "transition lock contention")
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled transition lock error = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancelled transition lock did not return")
			}
		})
	}
}

func TestCheckpointStandaloneDecisionWrappersPropagateUnlockErrors(t *testing.T) {
	t.Run("acknowledgement", func(t *testing.T) {
		store := NewMemoryCheckpointPendingStore()
		_, witnesses, request, receipt := prepareResolvedWitnessOperation(t, store)
		ack, err := witnesses[0].Acknowledge(context.Background(), request, receipt)
		if err != nil {
			t.Fatal(err)
		}
		unlockErr := errors.New("injected transition unlock failure")
		store.transitionUnlockErr = unlockErr
		err = store.RecordAcknowledgement(context.Background(), request, receipt, ack, CheckpointWitnessTrust{
			ID: witnesses[0].id, PublicKey: witnesses[0].private.Public().(ed25519.PublicKey), Witness: witnesses[0],
		})
		if !errors.Is(err, unlockErr) {
			t.Fatalf("acknowledgement wrapper dropped unlock error: %v", err)
		}
	})

	t.Run("equivocation", func(t *testing.T) {
		store := NewMemoryCheckpointPendingStore()
		_, witnesses, request, receipt := prepareResolvedWitnessOperation(t, store)
		original, err := witnesses[0].Acknowledge(context.Background(), request, receipt)
		if err != nil {
			t.Fatal(err)
		}
		trust := CheckpointWitnessTrust{
			ID: witnesses[0].id, PublicKey: witnesses[0].private.Public().(ed25519.PublicKey), Witness: witnesses[0],
		}
		if err := store.RecordAcknowledgement(context.Background(), request, receipt, original, trust); err != nil {
			t.Fatal(err)
		}
		conflicting := signedDecision(t, witnesses[0], original, "revoked")
		unlockErr := errors.New("injected transition unlock failure")
		store.transitionUnlockErr = unlockErr
		err = store.RecordEquivocation(context.Background(), request, receipt, original, conflicting, trust)
		if !errors.Is(err, unlockErr) {
			t.Fatalf("equivocation wrapper dropped unlock error: %v", err)
		}
	})

	t.Run("witness-quorum", func(t *testing.T) {
		store := NewMemoryCheckpointPendingStore()
		client, _, request, receipt := prepareResolvedWitnessOperation(t, store)
		unlockErr := errors.New("injected transition unlock failure")
		store.transitionUnlockErr = unlockErr
		_, err := client.acknowledgeWitnessQuorum(context.Background(), request, receipt, store)
		if !errors.Is(err, unlockErr) {
			t.Fatalf("witness acknowledgement wrapper dropped unlock error: %v", err)
		}
	})
}

func TestFileCheckpointStandaloneDecisionWrappersPropagateUnlockErrors(t *testing.T) {
	newStore := func(t *testing.T) *FileCheckpointPendingStore {
		t.Helper()
		store, ok := newTransitionTestStore(t, true).(*FileCheckpointPendingStore)
		if !ok {
			t.Fatal("file-backed transition store has unexpected type")
		}
		return store
	}

	t.Run("acknowledgement", func(t *testing.T) {
		store := newStore(t)
		_, witnesses, request, receipt := prepareResolvedWitnessOperation(t, store)
		ack, err := witnesses[0].Acknowledge(context.Background(), request, receipt)
		if err != nil {
			t.Fatal(err)
		}
		unlockErr := errors.New("injected transition unlock failure")
		store.transitionUnlockErr = unlockErr
		err = store.RecordAcknowledgement(context.Background(), request, receipt, ack, CheckpointWitnessTrust{
			ID: witnesses[0].id, PublicKey: witnesses[0].private.Public().(ed25519.PublicKey), Witness: witnesses[0],
		})
		if !errors.Is(err, unlockErr) {
			t.Fatalf("file acknowledgement wrapper dropped unlock error: %v", err)
		}
	})

	t.Run("equivocation", func(t *testing.T) {
		store := newStore(t)
		_, witnesses, request, receipt := prepareResolvedWitnessOperation(t, store)
		original, err := witnesses[0].Acknowledge(context.Background(), request, receipt)
		if err != nil {
			t.Fatal(err)
		}
		trust := CheckpointWitnessTrust{
			ID: witnesses[0].id, PublicKey: witnesses[0].private.Public().(ed25519.PublicKey), Witness: witnesses[0],
		}
		if err := store.RecordAcknowledgement(context.Background(), request, receipt, original, trust); err != nil {
			t.Fatal(err)
		}
		conflicting := signedDecision(t, witnesses[0], original, "revoked")
		unlockErr := errors.New("injected transition unlock failure")
		store.transitionUnlockErr = unlockErr
		err = store.RecordEquivocation(context.Background(), request, receipt, original, conflicting, trust)
		if !errors.Is(err, unlockErr) {
			t.Fatalf("file equivocation wrapper dropped unlock error: %v", err)
		}
	})
}

func TestFinalizationEvidenceIsDurableImmutableAndTamperEvident(t *testing.T) {
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
	client, _, request, receipt, _ := preparePersistedWitnessQuorum(t, store)
	acks, err := store.LoadAcknowledgements(context.Background(), request, receipt, client.Witnesses)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := client.finalizationEvidence(context.Background(), request, receipt, acks)
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := checkpointFinalizationID(request, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StoreFinalizationEvidence(context.Background(), request, receipt, operationID, evidence); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.LoadFinalizationEvidence(context.Background(), request, receipt, operationID)
	if err != nil || !found || !reflect.DeepEqual(evidence, loaded) {
		t.Fatalf("stored evidence mismatch: found=%t err=%v", found, err)
	}
	changed := evidence
	changed.PrimaryReceipt.Generation++
	if err := store.StoreFinalizationEvidence(context.Background(), request, receipt, operationID, changed); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("conflicting proof bundle replaced durable evidence: %v", err)
	}

	restarted, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetCheckpointTrustAnchors(client.PrimaryKey, client.Witnesses, client.Quorum); err != nil {
		t.Fatal(err)
	}
	recovered, found, err := restarted.LoadFinalizationEvidence(context.Background(), request, receipt, operationID)
	if err != nil || !found || !reflect.DeepEqual(evidence, recovered) {
		t.Fatalf("evidence did not survive restart: found=%t err=%v", found, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot checkpointPendingSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	key := checkpointPendingKey(request)
	entry := snapshot.Entries[key]
	entry.FinalizationEvidence.PrimaryReceipt.Generation++
	snapshot.Entries[key] = entry
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
	forgedStore, err := NewFileCheckpointPendingStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := forgedStore.LoadFinalizationEvidence(context.Background(), request, receipt, operationID); err == nil || found {
		t.Fatalf("tampered durable evidence accepted: found=%t err=%v", found, err)
	}
}

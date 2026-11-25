//go:build linux

package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
)

func durableFenceFixture(t *testing.T) (*FileCheckpointFencePrimary, []*FileCheckpointFenceWitness, ed25519.PrivateKey, CheckpointFenceRequest, string) {
	t.Helper()
	_, primaryKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"witness-a", "witness-b", "witness-c"}
	witnessKeys := make([]ed25519.PrivateKey, len(ids))
	trust := make([]CheckpointFenceWitnessTrust, len(ids))
	for i, id := range ids {
		_, witnessKeys[i], err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		trust[i] = CheckpointFenceWitnessTrust{ID: id, PublicKey: witnessKeys[i].Public().(ed25519.PublicKey)}
	}
	dir := t.TempDir()
	primary, err := OpenFileCheckpointFencePrimary(filepath.Join(dir, "primary", "fences.wal"), primaryKey, "witness-set-v1", trust)
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1000)
	primary.now = func() time.Time { return now }
	witnesses := make([]*FileCheckpointFenceWitness, len(ids))
	for i, id := range ids {
		witnesses[i], err = OpenFileCheckpointFenceWitness(filepath.Join(dir, id, "fences.wal"), id, witnessKeys[i], primaryKey.Public().(ed25519.PublicKey), "witness-set-v1", ids)
		if err != nil {
			t.Fatal(err)
		}
		witnesses[i].now = func() time.Time { return now }
	}
	_, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := CheckpointFenceRequest{
		Scope: CheckpointWitnessScope{
			DeviceID:       identity.DeviceID(deviceKey.Public().(ed25519.PublicKey)),
			AccountID:      "11111111-1111-4111-8111-111111111111",
			OrganizationID: "22222222-2222-4222-8222-222222222222",
		},
		ExpectedFenceGeneration: 0,
		ExpectedRevocationEpoch: 0,
		Action:                  CheckpointFenceFinalize,
		OperationID:             "durable-fence-op-0001",
		RequestSHA256:           sha256.Sum256([]byte("durable-request")),
		AuthorizationSHA256:     sha256.Sum256([]byte("durable-authorization")),
		WitnessSetVersion:       "witness-set-v1",
		WitnessIDs:              ids,
		ExpiresAtUnixMS:         5000,
	}
	return primary, witnesses, primaryKey, request, dir
}

func TestFileCheckpointFencePrimaryWitnessQuorumAndRestart(t *testing.T) {
	ctx := context.Background()
	primary, witnesses, primaryKey, request, dir := durableFenceFixture(t)
	token, err := primary.ReserveFence(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	acks := make([]CheckpointFenceAcknowledgement, 0, 2)
	for _, witness := range witnesses[:2] {
		ack, err := witness.CommitFence(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		acks = append(acks, ack)
	}
	if err := primary.CommitFence(ctx, token, acks); err != nil {
		t.Fatal(err)
	}
	witnesses[0].now = func() time.Time { return time.UnixMilli(token.ExpiresAtUnixMS) }
	recoveredAck, err := witnesses[0].CommitFence(ctx, token)
	if err != nil || !bytes.Equal(recoveredAck.Signature, acks[0].Signature) {
		t.Fatalf("exact witness acknowledgement not recoverable after expiry: %v", err)
	}
	operation, found, err := primary.LoadFence(ctx, request.Scope, request.OperationID)
	if err != nil || !found || !operation.Committed || operation.Token.Generation != 1 {
		t.Fatalf("committed operation not recovered: found=%v op=%+v err=%v", found, operation, err)
	}

	trust := make([]CheckpointFenceWitnessTrust, len(witnesses))
	ids := append([]string(nil), request.WitnessIDs...)
	for i, witness := range witnesses {
		trust[i] = CheckpointFenceWitnessTrust{ID: ids[i], PublicKey: witness.publicKey}
	}
	reopenedPrimary, err := OpenFileCheckpointFencePrimary(filepath.Join(dir, "primary", "fences.wal"), primaryKey, "witness-set-v1", trust)
	if err != nil {
		t.Fatal(err)
	}
	reopenedPrimary.now = func() time.Time { return time.UnixMilli(1000) }
	retried, err := reopenedPrimary.ReserveFence(ctx, request)
	if err != nil || !sameFenceToken(retried, token) {
		t.Fatalf("restart retry changed the signed token: err=%v", err)
	}
	if err := reopenedPrimary.CommitFence(ctx, token, acks[:1]); err != nil {
		t.Fatalf("exact committed retry should be idempotent: %v", err)
	}
	for i, witness := range witnesses[:2] {
		reopened, err := OpenFileCheckpointFenceWitness(filepath.Join(dir, ids[i], "fences.wal"), ids[i], witness.privateKey, primaryKey.Public().(ed25519.PublicKey), "witness-set-v1", ids)
		if err != nil {
			t.Fatal(err)
		}
		ack, found, err := reopened.LoadFence(ctx, request.Scope, token.Generation)
		if err != nil || !found || VerifyCheckpointFenceAcknowledgement(ack, ids[i], witness.publicKey) != nil {
			t.Fatalf("witness acknowledgement not recovered: found=%v err=%v", found, err)
		}
	}
}

func TestFileCheckpointFencePartialQuorumResumesExactReservation(t *testing.T) {
	ctx := context.Background()
	primary, witnesses, primaryKey, request, dir := durableFenceFixture(t)
	token, err := primary.ReserveFence(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	first, err := witnesses[0].CommitFence(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.CommitFence(ctx, token, []CheckpointFenceAcknowledgement{first}); !errors.Is(err, ErrCheckpointQuorum) {
		t.Fatalf("partial quorum unexpectedly committed: %v", err)
	}
	trust := make([]CheckpointFenceWitnessTrust, len(witnesses))
	for i, witness := range witnesses {
		trust[i] = CheckpointFenceWitnessTrust{ID: request.WitnessIDs[i], PublicKey: witness.publicKey}
	}
	restarted, err := OpenFileCheckpointFencePrimary(filepath.Join(dir, "primary", "fences.wal"), primaryKey, "witness-set-v1", trust)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return time.UnixMilli(1000) }
	retry, err := restarted.ReserveFence(ctx, request)
	if err != nil || !sameFenceToken(retry, token) {
		t.Fatalf("pending reservation did not survive restart exactly: %v", err)
	}
	second, err := witnesses[1].CommitFence(ctx, retry)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.CommitFence(ctx, retry, []CheckpointFenceAcknowledgement{first, second}); err != nil {
		t.Fatal(err)
	}
}

func TestFileCheckpointFenceRejectsConflictingOperationAndForgedAck(t *testing.T) {
	ctx := context.Background()
	primary, witnesses, primaryKey, request, _ := durableFenceFixture(t)
	token, err := primary.ReserveFence(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	conflict := request
	conflict.RequestSHA256 = sha256.Sum256([]byte("different request"))
	if _, err := primary.ReserveFence(ctx, conflict); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("conflicting operation ID accepted: %v", err)
	}
	acks := make([]CheckpointFenceAcknowledgement, 0, 2)
	for _, witness := range witnesses[:2] {
		ack, err := witness.CommitFence(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		acks = append(acks, ack)
	}
	acks[0].Signature[0] ^= 0xff
	if err := primary.CommitFence(ctx, token, acks); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("forged witness acknowledgement accepted: %v", err)
	}
	if err := primary.CommitFence(ctx, token, []CheckpointFenceAcknowledgement{acks[1]}); !errors.Is(err, ErrCheckpointQuorum) {
		t.Fatalf("single witness committed a three-member set: %v", err)
	}
	conflicting, err := witnesses[0].CommitFence(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	conflicting.TokenSHA256[0] ^= 0xff
	conflicting.Signature = ed25519.Sign(witnesses[0].privateKey, checkpointFenceAcknowledgementMessage(conflicting))
	if err := primary.CommitFence(ctx, token, []CheckpointFenceAcknowledgement{conflicting, acks[1]}); !errors.Is(err, ErrCheckpointWitnessDisagreement) {
		t.Fatalf("signed witness disagreement did not fail closed: %v", err)
	}
	_ = primaryKey
}

func TestFileCheckpointFenceWitnessRejectsSameGenerationEquivocation(t *testing.T) {
	ctx := context.Background()
	_, witnesses, primaryKey, request, _ := durableFenceFixture(t)
	token, err := SignCheckpointFenceToken(CheckpointFenceToken{
		Version: checkpointFenceVersion, Scope: request.Scope,
		ExpectedFenceGeneration: 0, Generation: 1,
		ExpectedRevocationEpoch: 0, ResultingRevocationEpoch: 0,
		Action: CheckpointFenceFinalize, OperationID: request.OperationID,
		RequestSHA256: request.RequestSHA256, AuthorizationSHA256: request.AuthorizationSHA256,
		PrimaryHeadGeneration: 0, PreviousFenceSHA256: [sha256.Size]byte{},
		WitnessSetVersion: request.WitnessSetVersion, WitnessIDs: request.WitnessIDs,
		ExpiresAtUnixMS: request.ExpiresAtUnixMS,
	}, primaryKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witnesses[0].CommitFence(ctx, token); err != nil {
		t.Fatal(err)
	}
	equivocation := cloneCheckpointFenceToken(token)
	equivocation.OperationID = "different-operation-at-generation-one"
	equivocation.Signature = nil
	equivocation, err = SignCheckpointFenceToken(equivocation, primaryKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witnesses[0].CommitFence(ctx, equivocation); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("same-generation equivocation accepted: %v", err)
	}
	reusedID := cloneCheckpointFenceToken(token)
	reusedID.ExpectedFenceGeneration = 1
	reusedID.Generation = 2
	reusedID.PreviousFenceSHA256, _ = CheckpointFenceTokenDigest(token)
	reusedID.Signature = nil
	reusedID, err = SignCheckpointFenceToken(reusedID, primaryKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witnesses[0].CommitFence(ctx, reusedID); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("witness accepted operation ID reuse at a later generation: %v", err)
	}
}

func TestFileCheckpointFenceRejectsExpiredTokenAndTruncatedTailRecovers(t *testing.T) {
	ctx := context.Background()
	primary, witnesses, primaryKey, request, dir := durableFenceFixture(t)
	token, err := primary.ReserveFence(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	witnesses[0].now = func() time.Time { return time.UnixMilli(token.ExpiresAtUnixMS) }
	if _, err := witnesses[0].CommitFence(ctx, token); !errors.Is(err, ErrCheckpointFenceExpired) {
		t.Fatalf("expired token accepted: %v", err)
	}
	journal := filepath.Join(dir, "primary", "fences.wal")
	file, err := os.OpenFile(journal, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("{incomplete")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	trust := make([]CheckpointFenceWitnessTrust, len(witnesses))
	for i, witness := range witnesses {
		trust[i] = CheckpointFenceWitnessTrust{ID: request.WitnessIDs[i], PublicKey: witness.publicKey}
	}
	reopened, err := OpenFileCheckpointFencePrimary(journal, primaryKey, "witness-set-v1", trust)
	if err != nil {
		t.Fatalf("truncated tail should be discarded during recovery: %v", err)
	}
	reopened.now = func() time.Time { return time.UnixMilli(1000) }
	retry, err := reopened.ReserveFence(ctx, request)
	if err != nil || !sameFenceToken(retry, token) {
		t.Fatalf("durable reservation lost after truncated tail recovery: %v", err)
	}
}

func TestFileCheckpointFenceConcurrentReservationsHaveSingleWinner(t *testing.T) {
	ctx := context.Background()
	primary, witnesses, primaryKey, request, dir := durableFenceFixture(t)
	trust := make([]CheckpointFenceWitnessTrust, len(witnesses))
	for i, witness := range witnesses {
		trust[i] = CheckpointFenceWitnessTrust{ID: request.WitnessIDs[i], PublicKey: witness.publicKey}
	}
	secondPrimary, err := OpenFileCheckpointFencePrimary(filepath.Join(dir, "primary", "fences.wal"), primaryKey, "witness-set-v1", trust)
	if err != nil {
		t.Fatal(err)
	}
	secondPrimary.now = primary.now
	const workers = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			candidate := request
			candidate.OperationID = "concurrent-fence-operation-" + strconv.Itoa(i)
			store := primary
			if i%2 == 1 {
				store = secondPrimary
			}
			_, err := store.ReserveFence(ctx, candidate)
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("expected one durable reservation winner, got %d", successes)
	}
}

func sameFenceToken(a, b CheckpointFenceToken) bool {
	if a.Version != b.Version || a.Scope != b.Scope || a.ExpectedFenceGeneration != b.ExpectedFenceGeneration ||
		a.Generation != b.Generation || a.ExpectedRevocationEpoch != b.ExpectedRevocationEpoch ||
		a.ResultingRevocationEpoch != b.ResultingRevocationEpoch || a.Action != b.Action ||
		a.OperationID != b.OperationID || a.RequestSHA256 != b.RequestSHA256 ||
		a.AuthorizationSHA256 != b.AuthorizationSHA256 || a.PrimaryHeadGeneration != b.PrimaryHeadGeneration ||
		a.PrimaryHeadSHA256 != b.PrimaryHeadSHA256 || a.PreviousFenceSHA256 != b.PreviousFenceSHA256 ||
		a.WitnessSetVersion != b.WitnessSetVersion || a.ExpiresAtUnixMS != b.ExpiresAtUnixMS ||
		a.PrimaryKeyID != b.PrimaryKeyID || len(a.WitnessIDs) != len(b.WitnessIDs) ||
		len(a.Signature) != len(b.Signature) {
		return false
	}
	for i := range a.WitnessIDs {
		if a.WitnessIDs[i] != b.WitnessIDs[i] {
			return false
		}
	}
	for i := range a.Signature {
		if a.Signature[i] != b.Signature[i] {
			return false
		}
	}
	return true
}

func testRevocationFenceRequest(request CheckpointFenceRequest) CheckpointFenceRequest {
	signature := make([]byte, ed25519.SignatureSize)
	for i := range signature {
		signature[i] = byte(i + 1)
	}
	request.AuthorizationProof, _ = EncodeCheckpointRevocationAuthorizationProof(
		1000, request.ExpiresAtUnixMS, signature,
	)
	request.AuthorizationSHA256 = sha256.Sum256(request.AuthorizationProof)
	return request
}

func commitDurableFence(t *testing.T, primary *FileCheckpointFencePrimary, witnesses []*FileCheckpointFenceWitness, request CheckpointFenceRequest) CheckpointFenceToken {
	t.Helper()
	token, err := primary.ReserveFence(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	acks := make([]CheckpointFenceAcknowledgement, 0, 2)
	for _, witness := range witnesses[:2] {
		ack, err := witness.CommitFence(context.Background(), token)
		if err != nil {
			t.Fatal(err)
		}
		acks = append(acks, ack)
	}
	if err := primary.CommitFence(context.Background(), token, acks); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestDurableFenceOrderingRevocationFirstRejectsStaleFinalization(t *testing.T) {
	primary, witnesses, _, request, _ := durableFenceFixture(t)
	request.Action = CheckpointFenceRevoke
	request = testRevocationFenceRequest(request)
	request.OperationID = "durable-revoke-first"
	revoked := commitDurableFence(t, primary, witnesses, request)
	if revoked.Generation != 1 || revoked.ResultingRevocationEpoch != 1 {
		t.Fatalf("unexpected committed revoke: %+v", revoked)
	}
	staleFinalize := request
	staleFinalize.Action = CheckpointFenceFinalize
	staleFinalize.OperationID = "durable-stale-finalize"
	if _, err := primary.ReserveFence(context.Background(), staleFinalize); !errors.Is(err, ErrCheckpointStale) {
		t.Fatalf("stale finalization reserved after durable revoke: %v", err)
	}
}

func TestDurableFenceOrderingFinalizationFirstSurvivesLaterRevocation(t *testing.T) {
	primary, witnesses, _, request, _ := durableFenceFixture(t)
	request.Action = CheckpointFenceFinalize
	request.OperationID = "durable-finalize-first"
	finalized := commitDurableFence(t, primary, witnesses, request)
	revoke := request
	revoke.Action = CheckpointFenceRevoke
	revoke = testRevocationFenceRequest(revoke)
	revoke.OperationID = "durable-revoke-after-finalize"
	revoke.ExpectedFenceGeneration = finalized.Generation
	revoke.ExpectedRevocationEpoch = finalized.ResultingRevocationEpoch
	revoke.PreviousFenceSHA256, _ = CheckpointFenceTokenDigest(finalized)
	revoked := commitDurableFence(t, primary, witnesses, revoke)
	if revoked.Generation != finalized.Generation+1 || revoked.ResultingRevocationEpoch != finalized.ResultingRevocationEpoch+1 {
		t.Fatalf("revocation did not follow committed finalization: finalize=%+v revoke=%+v", finalized, revoked)
	}
	operation, found, err := primary.LoadFence(context.Background(), request.Scope, finalized.OperationID)
	if err != nil || !found || !operation.Committed || !sameFenceToken(operation.Token, finalized) {
		t.Fatalf("later revoke erased earlier finalization ordering: found=%v err=%v", found, err)
	}
}

func TestCheckpointFenceCoordinatorExecutesStrictMajority(t *testing.T) {
	primary, witnesses, primaryKey, request, _ := durableFenceFixture(t)
	clients := make([]CheckpointFenceWitnessClient, len(witnesses))
	for i, witness := range witnesses {
		clients[i] = CheckpointFenceWitnessClient{ID: request.WitnessIDs[i], PublicKey: witness.publicKey, Witness: witness}
	}
	coordinator := CheckpointFenceCoordinator{
		Primary: primary, PrimaryKey: primaryKey.Public().(ed25519.PublicKey),
		WitnessSetVersion: request.WitnessSetVersion, Witnesses: clients, Quorum: 2,
		Now: primary.now,
	}
	operation, err := coordinator.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !operation.Committed || operation.Token.OperationID != request.OperationID || len(operation.Acknowledgements) < 2 {
		t.Fatalf("coordinator returned without a committed strict majority: %+v", operation)
	}
}

func TestFileCheckpointFencePrimaryRejectsStaleFenceAndPrimaryHeads(t *testing.T) {
	primary, witnesses, _, request, _ := durableFenceFixture(t)
	first := commitDurableFence(t, primary, witnesses, request)
	staleFence := request
	staleFence.OperationID = "stale-previous-fence"
	staleFence.ExpectedFenceGeneration = first.Generation
	staleFence.PreviousFenceSHA256 = [sha256.Size]byte{}
	if _, err := primary.ReserveFence(context.Background(), staleFence); !errors.Is(err, ErrCheckpointStale) {
		t.Fatalf("stale previous-fence digest accepted: %v", err)
	}
	secondRequest := request
	secondRequest.OperationID = "next-primary-head"
	secondRequest.ExpectedFenceGeneration = first.Generation
	secondRequest.PreviousFenceSHA256, _ = CheckpointFenceTokenDigest(first)
	secondRequest.PrimaryHeadGeneration = 1
	secondRequest.PrimaryHeadSHA256 = sha256.Sum256([]byte("primary-head-generation-one"))
	second := commitDurableFence(t, primary, witnesses, secondRequest)
	rollback := secondRequest
	rollback.OperationID = "primary-head-rollback"
	rollback.ExpectedFenceGeneration = second.Generation
	rollback.PreviousFenceSHA256, _ = CheckpointFenceTokenDigest(second)
	rollback.PrimaryHeadGeneration = 0
	rollback.PrimaryHeadSHA256 = [sha256.Size]byte{}
	if _, err := primary.ReserveFence(context.Background(), rollback); !errors.Is(err, ErrCheckpointStale) {
		t.Fatalf("primary-head rollback accepted: %v", err)
	}
}

func TestCheckpointFenceCoordinatorSerializesConcurrentFinalizeAndRevoke(t *testing.T) {
	ctx := context.Background()
	replay := newDeterministicCheckpointProvider(t)
	_, _, _, endpoint, _ := makeCheckpointFixture(t, replay,
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222")
	coordinator := newTestFenceCoordinator(t, replay)
	primary := coordinator.Primary.(*testAtomicCheckpointPrimary)
	head, err := replay.Head(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	heads := []CheckpointFenceParticipantHead{{Endpoint: endpoint, Head: head}}
	scope := organizationCheckpointFenceScope(endpoint.OrganizationID)
	fenceHead, err := primary.FenceHead(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	primaryHeadDigest, err := checkpointFenceParticipantHeadDigest(heads)
	if err != nil {
		t.Fatal(err)
	}
	base := CheckpointFenceRequest{
		Scope: scope, Participants: []CheckpointEndpoint{endpoint},
		ExpectedFenceGeneration: fenceHead.Generation, ExpectedRevocationEpoch: fenceHead.RevocationEpoch,
		RequestSHA256:         sha256.Sum256([]byte("concurrent-fence-request")),
		AuthorizationSHA256:   sha256.Sum256([]byte("concurrent-fence-authorization")),
		PrimaryHeadGeneration: fenceHead.Generation + 1, PrimaryHeadSHA256: primaryHeadDigest,
		PreviousFenceSHA256: fenceHead.FenceDigest,
		WitnessSetVersion:   coordinator.WitnessSetVersion,
		WitnessIDs:          checkpointFenceClientIDs(coordinator.Witnesses),
		ExpiresAtUnixMS:     time.Now().Add(time.Minute).UnixMilli(),
	}
	finalize := base
	finalize.Action = CheckpointFenceFinalize
	finalize.OperationID = "concurrent-finalize"
	revoke := base
	revoke.Action = CheckpointFenceRevoke
	revoke.OperationID, err = CheckpointRevocationOperationID(endpoint, endpoint.RevocationEpoch+1)
	if err != nil {
		t.Fatal(err)
	}
	revoke.AuthorizationProof, err = (testCheckpointRevocationProofProvider{
		privateKey: append(ed25519.PrivateKey(nil), primary.revocationPrivateKey...),
	}).CheckpointRevocationProof(ctx, CheckpointRevocationAuthorizationRequest{
		Endpoint: endpoint, NextEpoch: endpoint.RevocationEpoch + 1,
		OperationID: revoke.OperationID, Participants: []CheckpointEndpoint{endpoint},
	})
	if err != nil {
		t.Fatal(err)
	}
	revoke.AuthorizationSHA256 = sha256.Sum256(revoke.AuthorizationProof)

	start := make(chan struct{})
	type outcome struct {
		operation CheckpointFenceOperation
		err       error
	}
	results := make(chan outcome, 2)
	for _, candidate := range []CheckpointFenceRequest{finalize, revoke} {
		candidate := candidate
		go func() {
			<-start
			operation, err := coordinator.ExecuteWithCheckpointHeads(ctx, candidate, heads)
			results <- outcome{operation: operation, err: err}
		}()
	}
	close(start)
	successes := 0
	stale := 0
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err == nil {
			if !result.operation.Committed || result.operation.Token.Generation != 1 {
				t.Fatalf("winner was not durably committed at generation one: %+v", result.operation)
			}
			successes++
			continue
		}
		if errors.Is(result.err, ErrCheckpointStale) {
			stale++
			continue
		}
		t.Fatalf("unexpected concurrent fencing outcome: %v", result.err)
	}
	if successes != 1 || stale != 1 {
		t.Fatalf("expected one committed winner and one stale loser, success=%d stale=%d", successes, stale)
	}
}

func TestFileCheckpointFencePrimaryRecoversPreExpiryQuorumAfterExpiry(t *testing.T) {
	ctx := context.Background()
	primary, witnesses, _, request, _ := durableFenceFixture(t)
	token, err := primary.ReserveFence(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	acks := make([]CheckpointFenceAcknowledgement, 0, 2)
	for _, witness := range witnesses[:2] {
		ack, err := witness.CommitFence(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		acks = append(acks, ack)
	}
	primary.now = func() time.Time { return time.UnixMilli(token.ExpiresAtUnixMS + 1000) }
	if err := primary.CommitFence(ctx, token, acks); err != nil {
		t.Fatalf("durable pre-expiry quorum could not recover after lost response: %v", err)
	}
	operation, found, err := primary.LoadFence(ctx, request.Scope, request.OperationID)
	if err != nil || !found || !operation.Committed {
		t.Fatalf("pre-expiry quorum was not committed during recovery: found=%v err=%v", found, err)
	}
}

func TestCheckpointFenceCoordinatorRecoversQuorumWithExpiredNonVoter(t *testing.T) {
	primary, witnesses, primaryKey, request, _ := durableFenceFixture(t)
	token, err := primary.ReserveFence(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, witness := range witnesses[:2] {
		if _, err := witness.CommitFence(context.Background(), token); err != nil {
			t.Fatal(err)
		}
	}
	primary.now = func() time.Time { return time.UnixMilli(token.ExpiresAtUnixMS + 1000) }
	witnesses[2].now = func() time.Time { return time.UnixMilli(token.ExpiresAtUnixMS) }
	clients := make([]CheckpointFenceWitnessClient, len(witnesses))
	for i, witness := range witnesses {
		clients[i] = CheckpointFenceWitnessClient{ID: request.WitnessIDs[i], PublicKey: witness.publicKey, Witness: witness}
	}
	coordinator := CheckpointFenceCoordinator{
		Primary: primary, PrimaryKey: primaryKey.Public().(ed25519.PublicKey),
		WitnessSetVersion: request.WitnessSetVersion, Witnesses: clients, Quorum: 2,
		Now: primary.now,
	}
	operation, err := coordinator.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("two durable pre-expiry acknowledgements should recover quorum: %v", err)
	}
	if !operation.Committed || len(operation.Acknowledgements) != 2 {
		t.Fatalf("unexpected recovered operation: %+v", operation)
	}
}

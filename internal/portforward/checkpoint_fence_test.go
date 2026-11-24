package portforward

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/identity"
)

func validFenceToken(t *testing.T, action CheckpointFenceAction) (CheckpointFenceToken, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := CheckpointFenceToken{
		Version: checkpointFenceVersion,
		Scope: CheckpointWitnessScope{
			DeviceID:       identity.DeviceID(deviceKey.Public().(ed25519.PublicKey)),
			AccountID:      "11111111-1111-4111-8111-111111111111",
			OrganizationID: "22222222-2222-4222-8222-222222222222",
		},
		ExpectedFenceGeneration:  4,
		Generation:               5,
		ExpectedRevocationEpoch:  7,
		ResultingRevocationEpoch: 7,
		Action:                   action,
		OperationID:              "c173-fence-op-0001",
		RequestSHA256:            sha256.Sum256([]byte("request")),
		AuthorizationSHA256:      sha256.Sum256([]byte("authorization")),
		PrimaryHeadGeneration:    19,
		PrimaryHeadSHA256:        sha256.Sum256([]byte("primary-head")),
		PreviousFenceSHA256:      sha256.Sum256([]byte("previous-fence")),
		WitnessSetVersion:        "witness-set-v1",
		WitnessIDs:               []string{"witness-c", "witness-a", "witness-b"},
		ExpiresAtUnixMS:          2000,
	}
	if action == CheckpointFenceRevoke {
		token.ResultingRevocationEpoch++
	}
	signed, err := SignCheckpointFenceToken(token, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpointFenceToken(signed, publicKey, 1000); err != nil {
		t.Fatal(err)
	}
	return signed, privateKey
}

func TestCheckpointFenceTokenAuthenticatesCommonOrdering(t *testing.T) {
	token, privateKey := validFenceToken(t, CheckpointFenceFinalize)
	digest, err := CheckpointFenceTokenDigest(token)
	if err != nil {
		t.Fatal(err)
	}
	reordered := token
	reordered.WitnessIDs = []string{"witness-b", "witness-c", "witness-a"}
	reorderedDigest, err := CheckpointFenceTokenDigest(reordered)
	if err != nil || digest != reorderedDigest {
		t.Fatalf("witness ordering changed canonical digest: %v", err)
	}
	changed := token
	changed.Action = CheckpointFenceRevoke
	if _, err := CheckpointFenceTokenDigest(changed); !errors.Is(err, ErrCheckpointStale) {
		t.Fatalf("finalize token accepted a changed action/epoch: %v", err)
	}
	changed = token
	changed.Generation++
	if err := VerifyCheckpointFenceToken(changed, privateKey.Public().(ed25519.PublicKey), 1000); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("stale generation mutation accepted: %v", err)
	}
	if err := VerifyCheckpointFenceToken(token, privateKey.Public().(ed25519.PublicKey), token.ExpiresAtUnixMS); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("expired token accepted: %v", err)
	}
}

func TestCheckpointFenceTokenRequiresMonotonicActionEpoch(t *testing.T) {
	revoke, privateKey := validFenceToken(t, CheckpointFenceRevoke)
	if revoke.ResultingRevocationEpoch != revoke.ExpectedRevocationEpoch+1 {
		t.Fatal("revocation did not advance the epoch")
	}
	revoke.ResultingRevocationEpoch++
	if _, err := SignCheckpointFenceToken(revoke, privateKey); !errors.Is(err, ErrCheckpointStale) {
		t.Fatalf("non-monotonic revocation epoch accepted: %v", err)
	}

	finalize, finalizePrivateKey := validFenceToken(t, CheckpointFenceFinalize)
	finalize.ExpectedFenceGeneration++
	if err := VerifyCheckpointFenceToken(finalize, finalizePrivateKey.Public().(ed25519.PublicKey), 1000); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("unexpected expected-generation mutation accepted: %v", err)
	}
}

func TestCheckpointFenceTokenRejectsAmbiguousWitnessSet(t *testing.T) {
	token, privateKey := validFenceToken(t, CheckpointFenceFinalize)
	token.WitnessIDs = []string{"witness-a", "witness-a", "witness-b"}
	if _, err := SignCheckpointFenceToken(token, privateKey); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("duplicate witness identity accepted: %v", err)
	}
	if _, err := CheckpointFenceQuorum(2); !errors.Is(err, ErrCheckpointQuorum) {
		t.Fatalf("two-witness configuration accepted: %v", err)
	}
	if quorum, err := CheckpointFenceQuorum(3); err != nil || quorum != 2 {
		t.Fatalf("three-witness strict majority = %d, %v", quorum, err)
	}
	if quorum, err := CheckpointFenceQuorum(5); err != nil || quorum != 3 {
		t.Fatalf("five-witness strict majority = %d, %v", quorum, err)
	}
}


type fenceOrderingHarness struct {
	generation uint64
	revocationEpoch uint64
	witnessGenerations map[string]uint64
	base CheckpointFenceToken
	primaryKey ed25519.PrivateKey
}

func newFenceOrderingHarness(t *testing.T) *fenceOrderingHarness {
	t.Helper()
	base, key := validFenceToken(t, CheckpointFenceFinalize)
	witnessGenerations := make(map[string]uint64, len(base.WitnessIDs))
	for _, id := range base.WitnessIDs {
		witnessGenerations[id] = base.ExpectedFenceGeneration
	}
	return &fenceOrderingHarness{
		generation: base.ExpectedFenceGeneration,
		revocationEpoch: base.ExpectedRevocationEpoch,
		witnessGenerations: witnessGenerations,
		base: base,
		primaryKey: key,
	}
}

// apply models the durable compare-and-append rule; it is not a network service.
func (h *fenceOrderingHarness) apply(action CheckpointFenceAction, operationID string, expectedGeneration, expectedEpoch uint64) (CheckpointFenceToken, error) {
	if expectedGeneration != h.generation || expectedEpoch != h.revocationEpoch {
		return CheckpointFenceToken{}, ErrCheckpointStale
	}
	token := h.base
	token.ExpectedFenceGeneration = expectedGeneration
	token.Generation = expectedGeneration + 1
	token.ExpectedRevocationEpoch = expectedEpoch
	token.ResultingRevocationEpoch = expectedEpoch
	token.Action = action
	token.OperationID = operationID
	if action == CheckpointFenceRevoke {
		token.ResultingRevocationEpoch++
	}
	signed, err := SignCheckpointFenceToken(token, h.primaryKey)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	digest, err := CheckpointFenceTokenDigest(signed)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	quorum, err := CheckpointFenceQuorum(len(signed.WitnessIDs))
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	acknowledged := 0
	for _, id := range signed.WitnessIDs {
		if h.witnessGenerations[id] == expectedGeneration {
			h.witnessGenerations[id] = signed.Generation
			acknowledged++
		}
	}
	if acknowledged < quorum || h.generation != expectedGeneration {
		return CheckpointFenceToken{}, ErrCheckpointQuorum
	}
	_ = digest
	h.generation = signed.Generation
	h.revocationEpoch = signed.ResultingRevocationEpoch
	return signed, nil
}

func TestCheckpointFenceOrderingRevocationFirstRejectsFinalization(t *testing.T) {
	h := newFenceOrderingHarness(t)
	revoked, err := h.apply(CheckpointFenceRevoke, "revoke-first", h.generation, h.revocationEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Generation != 5 || revoked.ResultingRevocationEpoch != 8 {
		t.Fatalf("unexpected revocation fence: generation=%d epoch=%d", revoked.Generation, revoked.ResultingRevocationEpoch)
	}
	if _, err := h.apply(CheckpointFenceFinalize, "stale-finalize", 4, 7); !errors.Is(err, ErrCheckpointStale) {
		t.Fatalf("finalization based on pre-revocation generation was not rejected: %v", err)
	}
}

func TestCheckpointFenceOrderingFinalizationFirstRemainsValidAtOrderPoint(t *testing.T) {
	h := newFenceOrderingHarness(t)
	finalized, err := h.apply(CheckpointFenceFinalize, "finalize-first", h.generation, h.revocationEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpointFenceToken(finalized, h.primaryKey.Public().(ed25519.PublicKey), 1000); err != nil {
		t.Fatalf("finalization token invalid at its ordering point: %v", err)
	}
	revoked, err := h.apply(CheckpointFenceRevoke, "revoke-after-finalize", finalized.Generation, finalized.ResultingRevocationEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Generation != finalized.Generation+1 || revoked.ResultingRevocationEpoch != finalized.ResultingRevocationEpoch+1 {
		t.Fatalf("revocation did not follow finalization in the common order: finalize=%+v revoke=%+v", finalized, revoked)
	}
	if err := VerifyCheckpointFenceToken(finalized, h.primaryKey.Public().(ed25519.PublicKey), 1000); err != nil {
		t.Fatalf("later revocation retroactively invalidated committed finalization token: %v", err)
	}
}

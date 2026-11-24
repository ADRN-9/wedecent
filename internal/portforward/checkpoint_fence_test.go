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
			DeviceID: identity.DeviceID(deviceKey.Public().(ed25519.PublicKey)),
			AccountID: "11111111-1111-4111-8111-111111111111",
			OrganizationID: "22222222-2222-4222-8222-222222222222",
		},
		ExpectedFenceGeneration: 4,
		Generation: 5,
		ExpectedRevocationEpoch: 7,
		ResultingRevocationEpoch: 7,
		Action: action,
		OperationID: "c173-fence-op-0001",
		RequestSHA256: sha256.Sum256([]byte("request")),
		AuthorizationSHA256: sha256.Sum256([]byte("authorization")),
		PrimaryHeadGeneration: 19,
		PrimaryHeadSHA256: sha256.Sum256([]byte("primary-head")),
		PreviousFenceSHA256: sha256.Sum256([]byte("previous-fence")),
		WitnessSetVersion: "witness-set-v1",
		WitnessIDs: []string{"witness-c", "witness-a", "witness-b"},
		ExpiresAtUnixMS: 2000,
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

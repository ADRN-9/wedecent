package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func recoveryAuthorityFixture(t *testing.T) (RecoveryCheckpointRequest, RecoveryCheckpoint, map[string]ed25519.PublicKey) {
	t.Helper()
	var previous, state [sha256.Size]byte
	previousDigest := sha256.Sum256([]byte("previous-state"))
	stateDigest := sha256.Sum256([]byte("new-state"))
	copy(previous[:], previousDigest[:])
	copy(state[:], stateDigest[:])
	request, err := NewRecoveryCheckpointRequest("pairing-recovery/device-a", 7, previous, state)
	if err != nil {
		t.Fatal(err)
	}
	primaryPublic, primaryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := RecoveryCheckpoint{
		Scope: request.Scope, Generation: request.Generation,
		PreviousDigest: request.PreviousDigest, StateDigest: request.StateDigest,
		OperationID: request.OperationID,
	}
	primaryDigest := sha256.Sum256(primaryPublic)
	checkpoint.SignerKeyID = "ed25519:" + hex.EncodeToString(primaryDigest[:])
	message, err := RecoveryCheckpointSigningBytes(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Signature = ed25519.Sign(primaryPrivate, message)
	keys := make(map[string]ed25519.PublicKey)
	for _, id := range []string{"witness-a", "witness-b", "witness-c"} {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = publicKey
		checkpoint.Witnesses = append(checkpoint.Witnesses, RecoveryCheckpointWitness{
			ID: id, Signature: ed25519.Sign(privateKey, message),
		})
	}
	if err := VerifyRecoveryCheckpointSignature(checkpoint, primaryPublic); err != nil {
		t.Fatalf("valid pinned primary signature rejected: %v", err)
	}
	return request, checkpoint, keys
}

func TestValidateRecoveryCheckpointRequiresExactMonotonicQuorum(t *testing.T) {
	request, checkpoint, keys := recoveryAuthorityFixture(t)
	if err := ValidateRecoveryCheckpoint(request, checkpoint, keys, 2); err != nil {
		t.Fatalf("valid strict-majority checkpoint rejected: %v", err)
	}
}

func TestValidateRecoveryCheckpointRejectsStaleGeneration(t *testing.T) {
	request, checkpoint, keys := recoveryAuthorityFixture(t)
	checkpoint.Generation = request.ExpectedGeneration
	if err := ValidateRecoveryCheckpoint(request, checkpoint, keys, 2); !errors.Is(err, ErrRecoveryCheckpointStale) {
		t.Fatalf("stale generation accepted: %v", err)
	}
}

func TestValidateRecoveryCheckpointRejectsConflictingDigestAndOperation(t *testing.T) {
	request, checkpoint, keys := recoveryAuthorityFixture(t)
	checkpoint.StateDigest = sha256.Sum256([]byte("conflicting-state"))
	if err := ValidateRecoveryCheckpoint(request, checkpoint, keys, 2); !errors.Is(err, ErrRecoveryCheckpointConflict) {
		t.Fatalf("conflicting state digest accepted: %v", err)
	}
	request, checkpoint, keys = recoveryAuthorityFixture(t)
	request.OperationID = "duplicate-operation-with-different-payload"
	if err := ValidateRecoveryCheckpoint(request, checkpoint, keys, 2); !errors.Is(err, ErrRecoveryCheckpointConflict) {
		t.Fatalf("conflicting duplicate operation accepted: %v", err)
	}
}

func TestValidateRecoveryCheckpointRejectsDuplicateAndInsufficientWitnesses(t *testing.T) {
	request, checkpoint, keys := recoveryAuthorityFixture(t)
	checkpoint.Witnesses[1] = checkpoint.Witnesses[0]
	if err := ValidateRecoveryCheckpoint(request, checkpoint, keys, 2); !errors.Is(err, ErrRecoveryCheckpointConflict) {
		t.Fatalf("duplicate witness accepted: %v", err)
	}
	request, checkpoint, keys = recoveryAuthorityFixture(t)
	checkpoint.Witnesses = checkpoint.Witnesses[:1]
	if err := ValidateRecoveryCheckpoint(request, checkpoint, keys, 2); !errors.Is(err, ErrRecoveryCheckpointQuorum) {
		t.Fatalf("insufficient witness quorum accepted: %v", err)
	}
}

func TestValidateRecoveryCheckpointRejectsWitnessDisagreement(t *testing.T) {
	request, checkpoint, keys := recoveryAuthorityFixture(t)
	checkpoint.Witnesses[0].Signature[0] ^= 0xff
	if err := ValidateRecoveryCheckpoint(request, checkpoint, keys, 2); !errors.Is(err, ErrRecoveryCheckpointConflict) {
		t.Fatalf("witness signature disagreement accepted: %v", err)
	}
}

func TestRecoveryAuthorityTrustRequiresUniqueKeysAndPrimarySignature(t *testing.T) {
	previous := sha256.Sum256([]byte("authority-previous"))
	state := sha256.Sum256([]byte("authority-state"))
	request, err := NewRecoveryCheckpointRequest("pairing-recovery/device-a", 3, previous, state)
	if err != nil {
		t.Fatal(err)
	}
	primaryPublic, primaryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := RecoveryCheckpoint{Scope: request.Scope, Generation: request.Generation,
		PreviousDigest: request.PreviousDigest, StateDigest: request.StateDigest,
		OperationID: request.OperationID}
	primaryDigest := sha256.Sum256(primaryPublic)
	checkpoint.SignerKeyID = "ed25519:" + hex.EncodeToString(primaryDigest[:])
	message, err := RecoveryCheckpointSigningBytes(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.Signature = ed25519.Sign(primaryPrivate, message)
	trust := RecoveryAuthorityTrust{PrimaryKey: primaryPublic, WitnessKeys: make(map[string]ed25519.PublicKey), Quorum: 2}
	for _, id := range []string{"witness-a", "witness-b", "witness-c"} {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		trust.WitnessKeys[id] = publicKey
		checkpoint.Witnesses = append(checkpoint.Witnesses, RecoveryCheckpointWitness{ID: id, Signature: ed25519.Sign(privateKey, message)})
	}
	if err := ValidateRecoveryCheckpointWithTrust(request, checkpoint, trust); err != nil {
		t.Fatalf("valid fully authenticated checkpoint rejected: %v", err)
	}
	duplicate := RecoveryAuthorityTrust{PrimaryKey: primaryPublic, WitnessKeys: map[string]ed25519.PublicKey{
		"witness-a": trust.WitnessKeys["witness-a"],
		"witness-b": trust.WitnessKeys["witness-a"],
		"witness-c": trust.WitnessKeys["witness-c"],
	}, Quorum: 2}
	if err := duplicate.Validate(); !errors.Is(err, ErrRecoveryCheckpointConflict) {
		t.Fatalf("duplicate public key under distinct witness IDs accepted: %v", err)
	}
	checkpoint.Signature[0] ^= 0xff
	if err := ValidateRecoveryCheckpointWithTrust(request, checkpoint, trust); !errors.Is(err, ErrRecoveryCheckpointConflict) {
		t.Fatalf("invalid primary signature accepted by complete validation path: %v", err)
	}
}

func TestRecoveryAuthorityTrustRejectsPrimaryWitnessKeyReuse(t *testing.T) {
	primary, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := RecoveryAuthorityTrust{PrimaryKey: primary, WitnessKeys: map[string]ed25519.PublicKey{
		"witness-a": primary, "witness-b": otherA, "witness-c": otherB,
	}, Quorum: 2}
	if err := trust.Validate(); !errors.Is(err, ErrRecoveryCheckpointConflict) {
		t.Fatalf("primary key reused as witness key: %v", err)
	}
}

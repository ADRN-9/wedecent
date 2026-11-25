package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"errors"
	"testing"
	"time"
)

type testIndependentRecoveryAuthority struct {
	primaryPublic  ed25519.PublicKey
	primaryPrivate ed25519.PrivateKey
	trust          RecoveryAuthorityTrust
	witnessPrivate map[string]ed25519.PrivateKey
	head            RecoveryCheckpoint
	loseNextCommit  bool
}

func newTestIndependentRecoveryAuthority(t *testing.T) *testIndependentRecoveryAuthority {
	t.Helper()
	primaryPublic, primaryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &testIndependentRecoveryAuthority{primaryPublic: primaryPublic, primaryPrivate: primaryPrivate,
		witnessPrivate: make(map[string]ed25519.PrivateKey), head: RecoveryCheckpoint{Scope: "pairing-recovery/test-installation"}}
	a.trust = RecoveryAuthorityTrust{PrimaryKey: primaryPublic, WitnessKeys: make(map[string]ed25519.PublicKey), Quorum: 2}
	for _, id := range []string{"witness-a", "witness-b", "witness-c"} {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		a.trust.WitnessKeys[id] = publicKey
		a.witnessPrivate[id] = privateKey
	}
	return a
}

func (a *testIndependentRecoveryAuthority) SignArchive(_ context.Context, payload []byte) (string, []byte, error) {
	digest := sha256.Sum256(a.primaryPublic)
	return "ed25519:" + hex.EncodeToString(digest[:]), ed25519.Sign(a.primaryPrivate, payload), nil
}

func (a *testIndependentRecoveryAuthority) VerifyArchive(_ context.Context, keyID string, payload, signature []byte) error {
	digest := sha256.Sum256(a.primaryPublic)
	if keyID != "ed25519:"+hex.EncodeToString(digest[:]) || !ed25519.Verify(a.primaryPublic, payload, signature) {
		return ErrRecoveryCheckpointConflict
	}
	return nil
}

func (a *testIndependentRecoveryAuthority) LoadCheckpoint(_ context.Context, scope string) (RecoveryCheckpoint, error) {
	if a.head.Scope != scope {
		return RecoveryCheckpoint{}, ErrRecoveryCheckpointStale
	}
	return a.head, nil
}

func (a *testIndependentRecoveryAuthority) CommitCheckpoint(_ context.Context, request RecoveryCheckpointRequest) (RecoveryCheckpoint, error) {
	if request.Scope != a.head.Scope {
		return RecoveryCheckpoint{}, ErrRecoveryCheckpointConflict
	}
	if request.OperationID == a.head.OperationID && request.StateDigest == a.head.StateDigest {
		return a.head, nil
	}
	if request.ExpectedGeneration != a.head.Generation || request.PreviousDigest != a.head.StateDigest {
		return RecoveryCheckpoint{}, ErrRecoveryCheckpointStale
	}
	checkpoint := RecoveryCheckpoint{Scope: request.Scope, Generation: request.Generation,
		StateDigest: request.StateDigest, PreviousDigest: request.PreviousDigest, OperationID: request.OperationID}
	primaryDigest := sha256.Sum256(a.primaryPublic)
	checkpoint.SignerKeyID = "ed25519:" + hex.EncodeToString(primaryDigest[:])
	message, err := RecoveryCheckpointSigningBytes(checkpoint)
	if err != nil {
		return RecoveryCheckpoint{}, err
	}
	checkpoint.Signature = ed25519.Sign(a.primaryPrivate, message)
	for id, privateKey := range a.witnessPrivate {
		checkpoint.Witnesses = append(checkpoint.Witnesses, RecoveryCheckpointWitness{ID: id, Signature: ed25519.Sign(privateKey, message)})
	}
	a.head = checkpoint
	if a.loseNextCommit {
		a.loseNextCommit = false
		return RecoveryCheckpoint{}, errors.New("simulated lost commit response")
	}
	return checkpoint, nil
}

func (a *testIndependentRecoveryAuthority) VerifyCheckpoint(_ context.Context, checkpoint RecoveryCheckpoint) error {
	request, err := NewRecoveryCheckpointRequest(checkpoint.Scope, checkpoint.Generation-1, checkpoint.PreviousDigest, checkpoint.StateDigest)
	if err != nil {
		return err
	}
	return ValidateRecoveryCheckpointWithTrust(request, checkpoint, a.trust)
}

func (a *testIndependentRecoveryAuthority) MigrateLegacyArchive(context.Context, LegacyRecoveryMigrationRequest) (RecoveryCheckpoint, error) {
	return RecoveryCheckpoint{}, ErrRecoveryMigrationUntrusted
}

func TestPairingRecoveryUsesIndependentAuthorityAndResolvesLostCommitResponse(t *testing.T) {
	dir := recoveryTestDir(t)
	authority := newTestIndependentRecoveryAuthority(t)
	authority.loseNextCommit = true
	recovery, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := recovery.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	resolvePairingWithProof(t, dir, recovery, id, PairingOutcomeSuccess)
	if err := recovery.AcknowledgeResolved(id); err != nil {
		t.Fatalf("exact committed checkpoint was not recovered after lost response: %v", err)
	}
	archive, err := recovery.readArchive()
	if err != nil {
		t.Fatal(err)
	}
	if archive.AuthorityGeneration != 1 || archive.AuthorityCheckpoint.StateDigest == ([sha256.Size]byte{}) {
		t.Fatalf("archive lacks independent monotonic checkpoint: %+v", archive)
	}
	restarted, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatalf("independently authenticated archive failed restart: %v", err)
	}
	all, err := restarted.Records()
	if err != nil || len(all) != 1 {
		t.Fatalf("restart lost archived pairing record: %d %v", len(all), err)
	}
}

func TestPairingRecoveryAuthorityRejectsLegacyArchiveWithoutMigrationProof(t *testing.T) {
	dir := recoveryTestDir(t)
	legacy, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := legacy.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	resolveAndAcknowledgePairing(t, dir, legacy, id, PairingOutcomeSuccess)
	authority := newTestIndependentRecoveryAuthority(t)
	if _, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust); !errors.Is(err, ErrRecoveryMigrationUntrusted) {
		t.Fatalf("legacy archive accepted without independent migration proof: %v", err)
	}
}

func TestPairingRecoveryAuthorityRejectsReplacedLocalArchiveKey(t *testing.T) {
	dir := recoveryTestDir(t)
	authority := newTestIndependentRecoveryAuthority(t)
	recovery, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	id := "cccccccccccccccccccccccccccccccc"
	if err := recovery.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	resolveAndAcknowledgePairing(t, dir, recovery, id, PairingOutcomeSuccess)
	keyPath := dir + "/" + pairingArchiveKeyName
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust); err == nil {
		t.Fatal("replaced local archive key was accepted")
	}
}

func TestPairingRecoveryAuthorityRejectsDuplicateWitnessKeys(t *testing.T) {
	authority := newTestIndependentRecoveryAuthority(t)
	trust := authority.trust
	trust.WitnessKeys = map[string]ed25519.PublicKey{
		"witness-a": authority.trust.WitnessKeys["witness-a"],
		"witness-b": authority.trust.WitnessKeys["witness-a"],
		"witness-c": authority.trust.WitnessKeys["witness-c"],
	}
	if err := trust.Validate(); !errors.Is(err, ErrRecoveryCheckpointConflict) {
		t.Fatalf("duplicate witness key counted as independent identity: %v", err)
	}
	_ = time.Second
}

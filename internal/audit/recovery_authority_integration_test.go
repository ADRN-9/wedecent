package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"errors"
	"testing"
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

func (a *testIndependentRecoveryAuthority) MigrateLegacyArchive(_ context.Context, migration LegacyRecoveryMigrationRequest) (RecoveryCheckpoint, error) {
	var proof struct {
		StateDigest string `json:"state_digest"`
	}
	if migration.Scope != a.head.Scope || migration.MigrationOperationID == "" ||
		len(migration.AuthenticatedCheckpoint) == 0 || json.Unmarshal(migration.AuthenticatedCheckpoint, &proof) != nil {
		return RecoveryCheckpoint{}, ErrRecoveryMigrationUntrusted
	}
	digestBytes, err := hex.DecodeString(proof.StateDigest)
	if err != nil || len(digestBytes) != sha256.Size {
		return RecoveryCheckpoint{}, ErrRecoveryMigrationUntrusted
	}
	var stateDigest [sha256.Size]byte
	copy(stateDigest[:], digestBytes)
	if a.head.Generation == migration.ExpectedGeneration+1 && a.head.StateDigest == stateDigest {
		return a.head, nil
	}
	if a.head.Generation != migration.ExpectedGeneration {
		return RecoveryCheckpoint{}, ErrRecoveryCheckpointStale
	}
	request, err := NewRecoveryCheckpointRequest(migration.Scope, migration.ExpectedGeneration, a.head.StateDigest, stateDigest)
	if err != nil {
		return RecoveryCheckpoint{}, err
	}
	checkpoint, err := a.CommitCheckpoint(context.Background(), request)
	if err != nil {
		return RecoveryCheckpoint{}, err
	}
	return checkpoint, nil
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
}


func TestPairingRecoveryMigratesLegacyArchiveWithAuthenticatedAuthorityProof(t *testing.T) {
	dir := recoveryTestDir(t)
	legacy, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := "dddddddddddddddddddddddddddddddd"
	if err := legacy.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	resolveAndAcknowledgePairing(t, dir, legacy, id, PairingOutcomeSuccess)

	authority := newTestIndependentRecoveryAuthority(t)
	migration, err := OpenPairingRecoveryForMigration(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	legacyReader := *migration
	legacyReader.authority = nil
	archive, err := legacyReader.readArchive()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := pairingRecoveryArchiveUnsigned{Version: archive.Version, FirstSequence: archive.FirstSequence,
		LastSequence: archive.LastSequence, Checkpoint: archive.Checkpoint, Records: archive.Records,
		AuthorityGeneration: 1, AuthorityPreviousDigest: hex.EncodeToString(make([]byte, sha256.Size))}
	payload, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	proof, err := json.Marshal(struct {
		StateDigest string `json:"state_digest"`
	}{StateDigest: hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	authority.loseNextCommit = true
	if err := migration.MigrateLegacyArchive(context.Background(), proof); err != nil {
		t.Fatalf("authenticated migration did not recover exact lost commit: %v", err)
	}
	verified, err := migration.readArchive()
	if err != nil || verified.AuthorityGeneration != 1 || verified.AuthorityCheckpoint.StateDigest != digest {
		t.Fatalf("migrated archive lacks authenticated monotonic checkpoint: %+v %v", verified, err)
	}
}

func TestPairingRecoveryMigrationRejectsForgedStateDigestProof(t *testing.T) {
	dir := recoveryTestDir(t)
	legacy, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if err := legacy.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	resolveAndAcknowledgePairing(t, dir, legacy, id, PairingOutcomeSuccess)
	authority := newTestIndependentRecoveryAuthority(t)
	migration, err := OpenPairingRecoveryForMigration(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	forgedDigest := sha256.Sum256([]byte("forged archive state"))
	proof, err := json.Marshal(struct {
		StateDigest string `json:"state_digest"`
	}{StateDigest: hex.EncodeToString(forgedDigest[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.MigrateLegacyArchive(context.Background(), proof); !errors.Is(err, ErrRecoveryCheckpointConflict) {
		t.Fatalf("forged migration state digest accepted: %v", err)
	}
	legacyReader := *migration
	legacyReader.authority = nil
	stillLegacy, err := legacyReader.readArchive()
	if err != nil || stillLegacy.AuthorityGeneration != 0 {
		t.Fatalf("forged migration proof changed the local archive: %+v %v", stillLegacy, err)
	}
}


func TestPairingRecoveryAuthorityRejectsCompleteLocalSnapshotRollback(t *testing.T) {
	dir := recoveryTestDir(t)
	authority := newTestIndependentRecoveryAuthority(t)
	recovery, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	first := "ffffffffffffffffffffffffffffffff"
	if err := recovery.Begin(testRecoveryRecord(first)); err != nil {
		t.Fatal(err)
	}
	resolveAndAcknowledgePairing(t, dir, recovery, first, PairingOutcomeSuccess)
	archivePath := filepath.Join(dir, pairingArchiveFileName)
	snapshotPath := filepath.Join(dir, PairingOutcomeFileName)
	oldArchive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	oldSnapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	second := "99999999999999999999999999999999"
	if err := recovery.Begin(testRecoveryRecord(second)); err != nil {
		t.Fatal(err)
	}
	resolveAndAcknowledgePairing(t, dir, recovery, second, PairingOutcomeSuccess)
	if authority.head.Generation != 2 {
		t.Fatalf("expected two independent checkpoints, got generation %d", authority.head.Generation)
	}
	if err := os.WriteFile(archivePath, oldArchive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshotPath, oldSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust); !errors.Is(err, ErrRecoveryCheckpointStale) {
		t.Fatalf("restored complete local snapshot overrode newer independent head: %v", err)
	}
}

package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type testIndependentRecoveryAuthority struct {
	primaryPublic        ed25519.PublicKey
	primaryPrivate       ed25519.PrivateKey
	trust                RecoveryAuthorityTrust
	witnessPrivate       map[string]ed25519.PrivateKey
	head                 RecoveryCheckpoint
	heads                map[string]RecoveryCheckpoint
	loseNextCommit       bool
}

func newTestIndependentRecoveryAuthority(t *testing.T) *testIndependentRecoveryAuthority {
	t.Helper()
	primaryPublic, primaryPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &testIndependentRecoveryAuthority{primaryPublic: primaryPublic, primaryPrivate: primaryPrivate,
		witnessPrivate: make(map[string]ed25519.PrivateKey), head: RecoveryCheckpoint{Scope: "pairing-recovery/test-installation"},
		heads: make(map[string]RecoveryCheckpoint)}
	a.heads[a.head.Scope] = a.head
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
	if checkpoint, ok := a.heads[scope]; ok {
		return checkpoint, nil
	}
	return RecoveryCheckpoint{Scope: scope}, nil
}

func (a *testIndependentRecoveryAuthority) CommitCheckpoint(_ context.Context, request RecoveryCheckpointRequest) (RecoveryCheckpoint, error) {
	head, err := a.LoadCheckpoint(context.Background(), request.Scope)
	if err != nil {
		return RecoveryCheckpoint{}, err
	}
	if request.OperationID == head.OperationID && request.StateDigest == head.StateDigest {
		return head, nil
	}
	if request.ExpectedGeneration != head.Generation || request.PreviousDigest != head.StateDigest {
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
	a.heads[request.Scope] = checkpoint
	if request.Scope == a.head.Scope {
		a.head = checkpoint
	}
	if request.Scope == a.head.Scope && a.loseNextCommit {
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
		Scope         string `json:"scope"`
		ArchiveSHA256 string `json:"archive_sha256"`
		StateDigest   string `json:"state_digest"`
		Signature     string `json:"signature"`
	}
	head, _ := a.LoadCheckpoint(context.Background(), migration.Scope)
	if migration.MigrationOperationID == "" ||
		len(migration.AuthenticatedCheckpoint) == 0 ||
		json.Unmarshal(migration.AuthenticatedCheckpoint, &proof) != nil ||
		proof.Scope != migration.Scope ||
		proof.ArchiveSHA256 != hex.EncodeToString(migration.LegacyArchiveSHA256[:]) {
		return RecoveryCheckpoint{}, ErrRecoveryMigrationUntrusted
	}
	digestBytes, err := hex.DecodeString(proof.StateDigest)
	if err != nil || len(digestBytes) != sha256.Size {
		return RecoveryCheckpoint{}, ErrRecoveryMigrationUntrusted
	}
	signature, err := hex.DecodeString(proof.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return RecoveryCheckpoint{}, ErrRecoveryMigrationUntrusted
	}
	var stateDigest [sha256.Size]byte
	copy(stateDigest[:], digestBytes)
	message, err := testLegacyMigrationProofSigningBytes(proof.Scope, proof.ArchiveSHA256, proof.StateDigest)
	if err != nil || !ed25519.Verify(a.primaryPublic, message, signature) {
		return RecoveryCheckpoint{}, ErrRecoveryMigrationUntrusted
	}
	if head.Generation == migration.ExpectedGeneration+1 && head.StateDigest == stateDigest {
		return head, nil
	}
	if head.Generation != migration.ExpectedGeneration {
		return RecoveryCheckpoint{}, ErrRecoveryCheckpointStale
	}
	request, err := NewRecoveryCheckpointRequest(migration.Scope, migration.ExpectedGeneration, head.StateDigest, stateDigest)
	if err != nil {
		return RecoveryCheckpoint{}, err
	}
	checkpoint, err := a.CommitCheckpoint(context.Background(), request)
	if err != nil {
		return RecoveryCheckpoint{}, err
	}
	return checkpoint, nil
}

func testLegacyMigrationProofSigningBytes(scope, archiveSHA256, stateDigest string) ([]byte, error) {
	return json.Marshal(struct {
		Domain        string `json:"domain"`
		Scope         string `json:"scope"`
		ArchiveSHA256 string `json:"archive_sha256"`
		StateDigest   string `json:"state_digest"`
	}{
		Domain: "wedecent-test-authenticated-legacy-migration-v1",
		Scope: scope, ArchiveSHA256: archiveSHA256, StateDigest: stateDigest,
	})
}

func makeTestLegacyMigrationProof(t *testing.T, authority *testIndependentRecoveryAuthority, scope string, archive []byte, stateDigest [sha256.Size]byte) []byte {
	t.Helper()
	archiveDigest := sha256.Sum256(archive)
	proof := struct {
		Scope         string `json:"scope"`
		ArchiveSHA256 string `json:"archive_sha256"`
		StateDigest   string `json:"state_digest"`
		Signature     string `json:"signature"`
	}{
		Scope: scope,
		ArchiveSHA256: hex.EncodeToString(archiveDigest[:]),
		StateDigest: hex.EncodeToString(stateDigest[:]),
	}
	message, err := testLegacyMigrationProofSigningBytes(proof.Scope, proof.ArchiveSHA256, proof.StateDigest)
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature = hex.EncodeToString(ed25519.Sign(authority.primaryPrivate, message))
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
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
	legacyReader := &PairingRecovery{path: migration.path, archiveKey: migration.archiveKey}
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
	archiveBytes, err := os.ReadFile(filepath.Join(dir, pairingArchiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	proof := makeTestLegacyMigrationProof(t, authority, authority.head.Scope, archiveBytes, digest)
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
	if err := migration.MigrateLegacyArchive(context.Background(), proof); !errors.Is(err, ErrRecoveryMigrationUntrusted) {
		t.Fatalf("forged migration state digest accepted: %v", err)
	}
	legacyReader := &PairingRecovery{path: migration.path, archiveKey: migration.archiveKey}
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

func TestActivePairingLedgerRejectsRestoredOlderSnapshot(t *testing.T) {
	dir := recoveryTestDir(t)
	authority := newTestIndependentRecoveryAuthority(t)
	recovery, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	id := "abababababababababababababababab"
	if err := recovery.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, PairingOutcomeFileName)
	oldSnapshot, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.Complete(id, PairingOutcomeSuccess); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, oldSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust); !errors.Is(err, ErrRecoveryCheckpointStale) {
		t.Fatalf("restored older active ledger snapshot accepted: %v", err)
	}
}

func TestActivePairingLedgerRecoversInterruptedLocalPublication(t *testing.T) {
	dir := recoveryTestDir(t)
	authority := newTestIndependentRecoveryAuthority(t)
	recovery, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	recovery.beforeReplace = func() error { return errors.New("simulated process interruption after authority commit") }
	id := "acacacacacacacacacacacacacacacac"
	if err := recovery.Begin(testRecoveryRecord(id)); !errors.Is(err, ErrRecoveryCommitUncertain) {
		t.Fatalf("expected uncertain local publication, got %v", err)
	}
	restarted, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatalf("restart did not reconcile exact committed pending ledger operation: %v", err)
	}
	records, err := restarted.Records()
	if err != nil || len(records) != 1 || records[0].AttemptID != id {
		t.Fatalf("pending ledger mutation was not recovered: %+v %v", records, err)
	}
	if _, err := os.Lstat(restarted.path + ".authority-pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending marker was not removed after verified recovery: %v", err)
	}
}

func TestActivePairingLedgerMigrationRequiresProofAndPreservesSnapshot(t *testing.T) {
	dir := recoveryTestDir(t)
	legacy, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc"
	if err := legacy.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(legacy.path)
	if err != nil {
		t.Fatal(err)
	}
	authority := newTestIndependentRecoveryAuthority(t)
	migration, err := OpenPairingRecoveryForMigration(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := migration.read()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := pairingSnapshotDigest(unsignedPairingSnapshot(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	archiveBytes, err := os.ReadFile(migration.path)
	if err != nil {
		t.Fatal(err)
	}
	proof := makeTestLegacyMigrationProof(t, authority, migration.activeLedgerScope(), archiveBytes, digest)
	migration.beforeReplace = func() error { return errors.New("simulated interruption after active-ledger authority commit") }
	if err := migration.MigrateLegacyActiveLedger(context.Background(), proof); !errors.Is(err, ErrRecoveryCommitUncertain) {
		t.Fatalf("expected interrupted migration publication, got %v", err)
	}
	after, err := os.ReadFile(migration.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("interrupted migration changed legacy snapshot before finalization: %v", err)
	}
	restarted, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatalf("restart did not finalize proof-authenticated active ledger migration: %v", err)
	}
	records, err := restarted.Records()
	if err != nil || len(records) != 1 || records[0].AttemptID != id {
		t.Fatalf("migration did not preserve active recovery record: %+v %v", records, err)
	}
}

func TestActivePairingLedgerMigrationRejectsForgedProofWithoutMutation(t *testing.T) {
	dir := recoveryTestDir(t)
	legacy, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	if err := legacy.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(legacy.path)
	if err != nil {
		t.Fatal(err)
	}
	authority := newTestIndependentRecoveryAuthority(t)
	migration, err := OpenPairingRecoveryForMigration(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	forgedDigest := sha256.Sum256([]byte("forged active ledger state"))
	forged, err := json.Marshal(struct {
		StateDigest string `json:"state_digest"`
	}{StateDigest: hex.EncodeToString(forgedDigest[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.MigrateLegacyActiveLedger(context.Background(), forged); err == nil {
		t.Fatal("forged active ledger migration proof accepted")
	}
	after, err := os.ReadFile(migration.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("forged proof modified active ledger: %v", err)
	}
}

func TestActivePairingLedgerRejectsUnauthenticatedMatchingDigestProofWithoutMutation(t *testing.T) {
	dir := recoveryTestDir(t)
	legacy, err := OpenPairingRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := "dededededededededededededededede"
	if err := legacy.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(legacy.path)
	if err != nil {
		t.Fatal(err)
	}
	authority := newTestIndependentRecoveryAuthority(t)
	migration, err := OpenPairingRecoveryForMigration(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := migration.read()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := pairingSnapshotDigest(unsignedPairingSnapshot(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := json.Marshal(struct {
		StateDigest string `json:"state_digest"`
	}{StateDigest: hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.MigrateLegacyActiveLedger(context.Background(), proof); !errors.Is(err, ErrRecoveryMigrationUntrusted) {
		t.Fatalf("authority rejection was not propagated: %v", err)
	}
	after, err := os.ReadFile(migration.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rejected migration changed active ledger: %v", err)
	}
	if _, err := os.Lstat(migration.path + ".authority-pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected migration left a replayable pending intent: %v", err)
	}
	if authority.head.Generation != 0 {
		t.Fatalf("rejected migration advanced authority generation: %d", authority.head.Generation)
	}
}

func TestActivePairingLedgerRejectsCompetingCheckpointGeneration(t *testing.T) {
	dir := recoveryTestDir(t)
	authority := newTestIndependentRecoveryAuthority(t)
	recovery, err := OpenPairingRecoveryWithAuthority(dir, authority.head.Scope, authority, authority.trust)
	if err != nil {
		t.Fatal(err)
	}
	id := "efefefefefefefefefefefefefefefef"
	if err := recovery.Begin(testRecoveryRecord(id)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(recovery.path)
	if err != nil {
		t.Fatal(err)
	}
	scope := recovery.activeLedgerScope()
	head, err := authority.LoadCheckpoint(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	competingDigest := sha256.Sum256([]byte("independent competing state"))
	request, err := NewRecoveryCheckpointRequest(scope, head.Generation, head.StateDigest, competingDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.CommitCheckpoint(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := recovery.Complete(id, PairingOutcomeSuccess); !errors.Is(err, ErrRecoveryCheckpointStale) {
		t.Fatalf("stale active-ledger generation was accepted: %v", err)
	}
	after, err := os.ReadFile(recovery.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("stale mutation changed local active ledger: %v", err)
	}
}

func TestRecoveryCheckpointCommitIsIdempotentAndRejectsConflictingReplay(t *testing.T) {
	authority := newTestIndependentRecoveryAuthority(t)
	state := sha256.Sum256([]byte("committed pairing recovery state"))
	request, err := NewRecoveryCheckpointRequest(authority.head.Scope, 0, [sha256.Size]byte{}, state)
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.CommitCheckpoint(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := authority.CommitCheckpoint(context.Background(), request)
	if err != nil || !sameRecoveryCheckpoint(first, replayed) {
		t.Fatalf("exact checkpoint replay was not idempotent: %v", err)
	}
	conflictingState := sha256.Sum256([]byte("conflicting replay state"))
	conflict, err := NewRecoveryCheckpointRequest(authority.head.Scope, 0, [sha256.Size]byte{}, conflictingState)
	if err != nil {
		t.Fatal(err)
	}
	conflict.OperationID = request.OperationID
	if _, err := authority.CommitCheckpoint(context.Background(), conflict); !errors.Is(err, ErrRecoveryCheckpointStale) {
		t.Fatalf("conflicting replay was not rejected: %v", err)
	}
}

package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

var (
	ErrRecoveryAuthorityUnavailable = errors.New("independent recovery authority unavailable")
	ErrRecoveryCheckpointStale      = errors.New("recovery checkpoint generation is stale")
	ErrRecoveryCheckpointConflict   = errors.New("recovery checkpoint operation conflicts")
	ErrRecoveryCheckpointQuorum     = errors.New("recovery checkpoint witness quorum unavailable")
	ErrRecoveryCommitUncertain      = errors.New("recovery checkpoint commit outcome uncertain")
	ErrRecoveryMigrationUntrusted   = errors.New("legacy recovery archive lacks independent migration proof")
)

const recoveryCheckpointDomain = "wedecent-pairing-recovery-checkpoint-v1"

// RecoveryCheckpointRequest is a compare-and-advance request to an independently
// administered authority. OperationID is deterministic, so an exact retry is
// idempotent while reuse with different content is a conflict.
type RecoveryCheckpointRequest struct {
	Scope              string
	ExpectedGeneration uint64
	Generation         uint64
	PreviousDigest     [sha256.Size]byte
	StateDigest        [sha256.Size]byte
	OperationID        string
}

// RecoveryCheckpointWitness is one independently administered witness signature.
type RecoveryCheckpointWitness struct {
	ID        string
	Signature []byte
}

// RecoveryCheckpoint is the authority-signed monotonic head and strict-majority
// witness proof. Signatures are public-key verifiable; private keys never leave
// the authority or witness provider.
type RecoveryCheckpoint struct {
	Scope       string
	Generation  uint64
	StateDigest [sha256.Size]byte
	PreviousDigest [sha256.Size]byte
	OperationID string
	SignerKeyID string
	Signature   []byte
	Witnesses   []RecoveryCheckpointWitness
}

// LegacyRecoveryMigrationRequest requires an independently authenticated
// checkpoint supplied out of band. The legacy local MAC alone is not migration
// authority because a same-account attacker could have changed both archive and MAC.
type LegacyRecoveryMigrationRequest struct {
	Scope                       string
	LegacyArchiveSHA256         [sha256.Size]byte
	ExpectedGeneration          uint64
	AuthenticatedCheckpoint     []byte
	MigrationOperationID        string
}

// RecoveryAuthority is implemented by a remote or platform-backed provider.
// Implementations MUST keep signing keys non-exportable and independently
// administered. CommitCheckpoint MUST atomically compare generation/digest,
// enforce strict-majority witnesses, reject stale/conflicting/duplicate
// operations, and return the identical signed receipt for exact retries.
// If the caller cannot resolve a commit after a transport failure it must return
// ErrRecoveryCommitUncertain and the caller must not infer success or rollback.
type RecoveryAuthority interface {
	SignArchive(context.Context, []byte) (keyID string, signature []byte, err error)
	VerifyArchive(context.Context, string, []byte, []byte) error
	LoadCheckpoint(context.Context, string) (RecoveryCheckpoint, error)
	CommitCheckpoint(context.Context, RecoveryCheckpointRequest) (RecoveryCheckpoint, error)
	VerifyCheckpoint(context.Context, RecoveryCheckpoint) error
	MigrateLegacyArchive(context.Context, LegacyRecoveryMigrationRequest) (RecoveryCheckpoint, error)
}

// NewRecoveryCheckpointRequest creates the only accepted operation ID for a
// scope/generation/previous-digest/state-digest tuple.
func NewRecoveryCheckpointRequest(scope string, expected uint64, previous, state [sha256.Size]byte) (RecoveryCheckpointRequest, error) {
	if scope == "" || len(scope) > 256 || expected == ^uint64(0) || state == ([sha256.Size]byte{}) {
		return RecoveryCheckpointRequest{}, ErrRecoveryCheckpointConflict
	}
	request := RecoveryCheckpointRequest{
		Scope: scope, ExpectedGeneration: expected, Generation: expected + 1,
		PreviousDigest: previous, StateDigest: state,
	}
	message, err := recoveryCheckpointRequestBytes(request)
	if err != nil {
		return RecoveryCheckpointRequest{}, err
	}
	digest := sha256.Sum256(message)
	request.OperationID = hex.EncodeToString(digest[:])
	return request, nil
}

func recoveryCheckpointRequestBytes(request RecoveryCheckpointRequest) ([]byte, error) {
	if request.Scope == "" || len(request.Scope) > 256 ||
		request.ExpectedGeneration == ^uint64(0) ||
		request.Generation != request.ExpectedGeneration+1 ||
		request.StateDigest == ([sha256.Size]byte{}) {
		return nil, ErrRecoveryCheckpointConflict
	}
	var b bytes.Buffer
	b.WriteString(recoveryCheckpointDomain)
	b.WriteByte(0)
	if err := binary.Write(&b, binary.BigEndian, uint32(len(request.Scope))); err != nil {
		return nil, err
	}
	b.WriteString(request.Scope)
	if err := binary.Write(&b, binary.BigEndian, request.ExpectedGeneration); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, request.Generation); err != nil {
		return nil, err
	}
	b.Write(request.PreviousDigest[:])
	b.Write(request.StateDigest[:])
	return b.Bytes(), nil
}

// RecoveryCheckpointSigningBytes is the canonical payload signed by the
// independent primary and every witness.
func RecoveryCheckpointSigningBytes(checkpoint RecoveryCheckpoint) ([]byte, error) {
	request := RecoveryCheckpointRequest{
		Scope: checkpoint.Scope, ExpectedGeneration: checkpoint.Generation - 1,
		Generation: checkpoint.Generation, PreviousDigest: checkpoint.PreviousDigest,
		StateDigest: checkpoint.StateDigest, OperationID: checkpoint.OperationID,
	}
	if checkpoint.Generation == 0 {
		return nil, ErrRecoveryCheckpointStale
	}
	message, err := recoveryCheckpointRequestBytes(request)
	if err != nil {
		return nil, err
	}
	expected := sha256.Sum256(message)
	if checkpoint.OperationID != hex.EncodeToString(expected[:]) || checkpoint.SignerKeyID == "" || len(checkpoint.SignerKeyID) > 128 {
		return nil, ErrRecoveryCheckpointConflict
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(len(checkpoint.SignerKeyID))); err != nil {
		return nil, err
	}
	b.WriteString(checkpoint.SignerKeyID)
	return b.Bytes(), nil
}

// VerifyRecoveryCheckpointSignature binds the signer identity to the pinned
// non-exportable provider public key. The corresponding private key is never
// exported by the provider.
func VerifyRecoveryCheckpointSignature(checkpoint RecoveryCheckpoint, primaryKey ed25519.PublicKey) error {
	if len(primaryKey) != ed25519.PublicKeySize {
		return ErrRecoveryAuthorityUnavailable
	}
	keyDigest := sha256.Sum256(primaryKey)
	expectedKeyID := "ed25519:" + hex.EncodeToString(keyDigest[:])
	if checkpoint.SignerKeyID != expectedKeyID || len(checkpoint.Signature) != ed25519.SignatureSize {
		return ErrRecoveryCheckpointConflict
	}
	message, err := RecoveryCheckpointSigningBytes(checkpoint)
	if err != nil {
		return err
	}
	if !ed25519.Verify(primaryKey, message, checkpoint.Signature) {
		return ErrRecoveryCheckpointConflict
	}
	return nil
}

// ValidateRecoveryCheckpoint verifies the exact CAS transition and strict-majority
// signatures against pre-pinned public keys. The caller must also call the
// provider's VerifyCheckpoint to enforce the configured primary signer identity.
func ValidateRecoveryCheckpoint(
	request RecoveryCheckpointRequest,
	checkpoint RecoveryCheckpoint,
	witnessKeys map[string]ed25519.PublicKey,
	quorum int,
) error {
	requestBytes, err := recoveryCheckpointRequestBytes(request)
	if err != nil {
		return err
	}
	expectedID := sha256.Sum256(requestBytes)
	if request.OperationID != hex.EncodeToString(expectedID[:]) {
		return ErrRecoveryCheckpointConflict
	}
	if checkpoint.Scope != request.Scope || checkpoint.Generation != request.Generation ||
		checkpoint.PreviousDigest != request.PreviousDigest || checkpoint.StateDigest != request.StateDigest ||
		checkpoint.OperationID != request.OperationID {
		if checkpoint.Generation <= request.ExpectedGeneration {
			return ErrRecoveryCheckpointStale
		}
		return ErrRecoveryCheckpointConflict
	}
	if len(witnessKeys) < 3 || quorum < 2 || quorum <= len(witnessKeys)/2 || quorum > len(witnessKeys) {
		return ErrRecoveryCheckpointQuorum
	}
	message, err := RecoveryCheckpointSigningBytes(checkpoint)
	if err != nil {
		return err
	}
	if len(checkpoint.Signature) != ed25519.SignatureSize {
		return ErrRecoveryAuthorityUnavailable
	}
	seen := make(map[string]struct{}, len(checkpoint.Witnesses))
	for _, witness := range checkpoint.Witnesses {
		key, ok := witnessKeys[witness.ID]
		if !ok || len(key) != ed25519.PublicKeySize || len(witness.Signature) != ed25519.SignatureSize {
			return ErrRecoveryCheckpointConflict
		}
		if _, duplicate := seen[witness.ID]; duplicate {
			return ErrRecoveryCheckpointConflict
		}
		seen[witness.ID] = struct{}{}
		if !ed25519.Verify(key, message, witness.Signature) {
			return ErrRecoveryCheckpointConflict
		}
	}
	if len(seen) < quorum {
		return ErrRecoveryCheckpointQuorum
	}
	return nil
}

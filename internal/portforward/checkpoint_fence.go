package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

const (
	checkpointFenceVersion uint32 = 1
	checkpointFenceDomain         = "wedecent-checkpoint-fence-token-v1"
)

type CheckpointFenceAction string

const (
	CheckpointFenceFinalize CheckpointFenceAction = "finalize"
	CheckpointFenceRevoke   CheckpointFenceAction = "revoke"
)

// CheckpointFenceToken is the primary-signed ordering decision shared by finalize
// and revoke. Generation is the next durable fence generation, not a client counter.
type CheckpointFenceToken struct {
	Version                  uint32
	Scope                    CheckpointWitnessScope
	ExpectedFenceGeneration  uint64
	Generation               uint64
	ExpectedRevocationEpoch  uint64
	ResultingRevocationEpoch uint64
	Action                   CheckpointFenceAction
	OperationID              string
	RequestSHA256            [sha256.Size]byte
	AuthorizationSHA256      [sha256.Size]byte
	PrimaryHeadGeneration    uint64
	PrimaryHeadSHA256        [sha256.Size]byte
	PreviousFenceSHA256      [sha256.Size]byte
	WitnessSetVersion        string
	WitnessIDs               []string
	ExpiresAtUnixMS          int64
	PrimaryKeyID             string
	Signature                []byte
}

// CheckpointFenceAcknowledgement attests that one witness advanced to this token.
type CheckpointFenceAcknowledgement struct {
	WitnessID    string
	TokenSHA256  [sha256.Size]byte
	Generation   uint64
	Action       CheckpointFenceAction
	OperationID  string
	WitnessKeyID       string
	CommittedAtUnixMS  int64
	Signature          []byte
}

// CheckpointFenceQuorum returns the strict majority for a fixed witness set.
func CheckpointFenceQuorum(witnessCount int) (int, error) {
	if witnessCount < 3 || witnessCount > 31 {
		return 0, ErrCheckpointQuorum
	}
	return witnessCount/2 + 1, nil
}

// CheckpointFencingPrimary is the durable ordering authority. ReserveFence must
// compare the expected generation and persist the operation ID atomically.
// Exact retries return the identical token; conflicting retries fail closed.
type CheckpointFencingPrimary interface {
	ReserveFence(context.Context, CheckpointFenceRequest) (CheckpointFenceToken, error)
	CommitFence(context.Context, CheckpointFenceToken, []CheckpointFenceAcknowledgement) error
	LoadFence(context.Context, CheckpointWitnessScope, string) (CheckpointFenceOperation, bool, error)
}

// CheckpointFencingWitness advances an independently stored monotonic generation.
type CheckpointFencingWitness interface {
	CommitFence(context.Context, CheckpointFenceToken) (CheckpointFenceAcknowledgement, error)
	LoadFence(context.Context, CheckpointWitnessScope, uint64) (CheckpointFenceAcknowledgement, bool, error)
}

type CheckpointFenceRequest struct {
	Scope                   CheckpointWitnessScope
	ExpectedFenceGeneration uint64
	ExpectedRevocationEpoch uint64
	Action                  CheckpointFenceAction
	OperationID             string
	RequestSHA256           [sha256.Size]byte
	AuthorizationSHA256     [sha256.Size]byte
	PrimaryHeadGeneration   uint64
	PrimaryHeadSHA256       [sha256.Size]byte
	PreviousFenceSHA256     [sha256.Size]byte
	WitnessSetVersion       string
	WitnessIDs              []string
	ExpiresAtUnixMS         int64
}

// CheckpointFenceTokenDigest hashes the canonical token payload, excluding signature.
func CheckpointFenceTokenDigest(token CheckpointFenceToken) ([sha256.Size]byte, error) {
	message, err := checkpointFenceTokenMessage(token)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(message), nil
}

// VerifyCheckpointFenceToken validates transition semantics, fixed quorum membership,
// expiry, key identity and the primary signature.
func VerifyCheckpointFenceToken(token CheckpointFenceToken, primaryKey ed25519.PublicKey, nowUnixMS int64) error {
	message, err := checkpointFenceTokenMessage(token)
	if err != nil || len(primaryKey) != ed25519.PublicKeySize ||
		token.PrimaryKeyID != checkpointProviderKeyID(primaryKey) ||
		len(token.Signature) != ed25519.SignatureSize ||
		token.ExpiresAtUnixMS <= nowUnixMS ||
		!ed25519.Verify(primaryKey, message, token.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

// SignCheckpointFenceToken signs a fully validated primary ordering decision.
func SignCheckpointFenceToken(token CheckpointFenceToken, primaryKey ed25519.PrivateKey) (CheckpointFenceToken, error) {
	if len(primaryKey) != ed25519.PrivateKeySize {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	token.PrimaryKeyID = checkpointProviderKeyID(primaryKey.Public().(ed25519.PublicKey))
	message, err := checkpointFenceTokenMessage(token)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	token.Signature = ed25519.Sign(primaryKey, message)
	return token, nil
}

func checkpointFenceTokenMessage(token CheckpointFenceToken) ([]byte, error) {
	if token.Version != checkpointFenceVersion || !validCheckpointFenceScope(token.Scope) ||
		(token.Action != CheckpointFenceFinalize && token.Action != CheckpointFenceRevoke) ||
		token.OperationID == "" || len(token.OperationID) > 128 ||
		token.RequestSHA256 == ([sha256.Size]byte{}) ||
		token.AuthorizationSHA256 == ([sha256.Size]byte{}) ||
		token.Generation == 0 || token.ExpectedFenceGeneration == ^uint64(0) ||
		token.Generation != token.ExpectedFenceGeneration+1 ||
		token.WitnessSetVersion == "" || len(token.WitnessSetVersion) > 128 ||
		len(token.WitnessIDs) < 3 || token.ExpiresAtUnixMS <= 0 ||
		(token.PrimaryHeadGeneration == 0 && token.PrimaryHeadSHA256 != ([sha256.Size]byte{})) ||
		(token.PrimaryHeadGeneration > 0 && token.PrimaryHeadSHA256 == ([sha256.Size]byte{})) ||
		(token.ExpectedFenceGeneration == 0 && token.PreviousFenceSHA256 != ([sha256.Size]byte{})) ||
		(token.ExpectedFenceGeneration > 0 && token.PreviousFenceSHA256 == ([sha256.Size]byte{})) ||
		token.PrimaryKeyID == "" || len(token.PrimaryKeyID) > 128 {
		return nil, ErrCheckpointIntegrity
	}
	if _, err := CheckpointFenceQuorum(len(token.WitnessIDs)); err != nil {
		return nil, err
	}
	if token.Action == CheckpointFenceFinalize &&
		token.ResultingRevocationEpoch != token.ExpectedRevocationEpoch {
		return nil, ErrCheckpointStale
	}
	if token.Action == CheckpointFenceRevoke &&
		(token.ExpectedRevocationEpoch == ^uint64(0) ||
			token.ResultingRevocationEpoch != token.ExpectedRevocationEpoch+1) {
		return nil, ErrCheckpointStale
	}
	ids := append([]string(nil), token.WitnessIDs...)
	sort.Strings(ids)
	for i, id := range ids {
		if id == "" || len(id) > 128 || (i > 0 && ids[i-1] == id) {
			return nil, ErrCheckpointIntegrity
		}
	}
	var b bytes.Buffer
	putString := func(value string) error {
		if len(value) > int(^uint32(0)) {
			return ErrCheckpointIntegrity
		}
		if err := binary.Write(&b, binary.BigEndian, uint32(len(value))); err != nil {
			return err
		}
		_, err := b.WriteString(value)
		return err
	}
	for _, value := range []string{
		checkpointFenceDomain, token.Scope.DeviceID, token.Scope.AccountID,
		token.Scope.OrganizationID, string(token.Action), token.OperationID,
		token.WitnessSetVersion, token.PrimaryKeyID,
	} {
		if err := putString(value); err != nil {
			return nil, err
		}
	}
	for _, value := range []uint64{
		uint64(token.Version), token.ExpectedFenceGeneration, token.Generation,
		token.ExpectedRevocationEpoch, token.ResultingRevocationEpoch,
		token.PrimaryHeadGeneration, uint64(token.ExpiresAtUnixMS),
		uint64(len(ids)),
	} {
		if err := binary.Write(&b, binary.BigEndian, value); err != nil {
			return nil, err
		}
	}
	b.Write(token.RequestSHA256[:])
	b.Write(token.AuthorizationSHA256[:])
	b.Write(token.PrimaryHeadSHA256[:])
	b.Write(token.PreviousFenceSHA256[:])
	for _, id := range ids {
		if err := putString(id); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func validCheckpointFenceScope(scope CheckpointWitnessScope) bool {
	return deviceIDPattern.MatchString(scope.DeviceID) &&
		canonicalUUID(scope.AccountID) && canonicalUUID(scope.OrganizationID)
}

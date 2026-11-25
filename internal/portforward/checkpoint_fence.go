package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/binary"
	"sort"
)

const (
	checkpointFenceVersion           uint32 = 1
	checkpointFenceRevocationVersion uint32 = 2
	checkpointFenceDomain                   = "wedecent-checkpoint-fence-token-v1"
	checkpointFenceRevocationDomain         = "wedecent-checkpoint-fence-token-v2"
)

type CheckpointFenceAction string

const (
	CheckpointFenceFinalize CheckpointFenceAction = "finalize"
	CheckpointFenceRevoke   CheckpointFenceAction = "revoke"
)

func checkpointFenceVersionForAction(action CheckpointFenceAction) (uint32, error) {
	switch action {
	case CheckpointFenceFinalize:
		return checkpointFenceVersion, nil
	case CheckpointFenceRevoke:
		return checkpointFenceRevocationVersion, nil
	default:
		return 0, ErrCheckpointIntegrity
	}
}

// CheckpointFenceToken is the primary-signed ordering reservation shared by
// finalize and revoke. It is not authorization until its quorum commit is durable.
// Generation is the next durable fence generation, not a client counter.
type CheckpointFenceToken struct {
	Version                  uint32
	Scope                    CheckpointWitnessScope
	Participants             []CheckpointEndpoint
	ExpectedFenceGeneration  uint64
	Generation               uint64
	ExpectedRevocationEpoch  uint64
	ResultingRevocationEpoch uint64
	Action                   CheckpointFenceAction
	OperationID              string
	RequestSHA256            [sha256.Size]byte
	AuthorizationSHA256      [sha256.Size]byte
	AuthorizationProof       []byte
	AuthorizationProofIssuedAtUnixMS int64
	AuthorizationProofExpiresAtUnixMS int64
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
	WitnessID         string
	TokenSHA256       [sha256.Size]byte
	Generation        uint64
	Action            CheckpointFenceAction
	OperationID       string
	WitnessKeyID      string
	CommittedAtUnixMS int64
	Signature         []byte
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

type CheckpointFenceParticipantHead struct {
	Endpoint CheckpointEndpoint
	Head     CheckpointHead
}

type CheckpointFenceHead struct {
	Generation            uint64
	RevocationEpoch       uint64
	FenceDigest           [sha256.Size]byte
	PrimaryHeadGeneration uint64
	PrimaryHeadSHA256     [sha256.Size]byte
	PendingOperationID    string
	LastOperationID       string
	LastAction            CheckpointFenceAction
}

type CheckpointFenceHeadReader interface {
	FenceHead(context.Context, CheckpointWitnessScope) (CheckpointFenceHead, error)
}

// CheckpointAuthorityBinding identifies the exact checkpoint authority shared
// by replay operations and atomic fencing. The fence signing key remains separate.
type CheckpointAuthorityBinding interface {
	CheckpointAuthorityKeyID() string
}

// CheckpointFenceAtomicPrimary must independently validate revocation proof,
// compare the complete signed participant-head vector against the authoritative
// checkpoint store, and reserve in the same transaction. Commit must revalidate
// heads, verify strict-majority acknowledgements, and atomically advance the target
// revocation head with the quorum-backed fence commit.
type CheckpointFenceAtomicPrimary interface {
	ReserveFenceWithCheckpointHeads(context.Context, CheckpointFenceRequest, []CheckpointFenceParticipantHead) (CheckpointFenceToken, error)
	CommitFenceWithCheckpointHeads(context.Context, CheckpointFenceToken, []CheckpointFenceAcknowledgement, []CheckpointFenceParticipantHead) error
}

// CheckpointFencingWitness advances an independently stored monotonic generation.
type CheckpointFencingWitness interface {
	CommitFence(context.Context, CheckpointFenceToken) (CheckpointFenceAcknowledgement, error)
	LoadFence(context.Context, CheckpointWitnessScope, uint64) (CheckpointFenceAcknowledgement, bool, error)
}

type CheckpointFenceRequest struct {
	Scope                   CheckpointWitnessScope
	Participants            []CheckpointEndpoint
	AuthorizationProof      []byte
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


// CheckpointRevocationOperationID returns the stable operation identity used by
// both the proof issuer and the PostgreSQL fence adapter.
func CheckpointRevocationOperationID(endpoint CheckpointEndpoint, next uint64) (string, error) {
	if !validCheckpointEndpoint(endpoint) || endpoint.RevocationEpoch == ^uint64(0) ||
		next != endpoint.RevocationEpoch+1 {
		return "", ErrCheckpointStale
	}
	fingerprint := checkpointRevocationFingerprint(endpoint, next)
	return checkpointFenceOperationID(CheckpointFenceRevoke,
		hex.EncodeToString(fingerprint[:]), endpoint.OrganizationID), nil
}

type CheckpointRevocationAuthorizationRequest struct {
	Endpoint        CheckpointEndpoint
	NextEpoch       uint64
	OperationID     string
	Participants    []CheckpointEndpoint
	IssuedAtUnixMS  int64
	ExpiresAtUnixMS int64
}

const checkpointRevocationProofEnvelopeVersion uint32 = 1
const checkpointRevocationProofEnvelopeSize = 4 + 4 + 8 + 8 + ed25519.SignatureSize

type checkpointRevocationProofEnvelope struct {
	IssuedAtUnixMS  int64
	ExpiresAtUnixMS int64
	Signature       []byte
}

// EncodeCheckpointRevocationAuthorizationProof encodes the signed proof claims
// returned by a control-plane authorization service.
func EncodeCheckpointRevocationAuthorizationProof(issuedAtUnixMS, expiresAtUnixMS int64, signature []byte) ([]byte, error) {
	if issuedAtUnixMS <= 0 || expiresAtUnixMS <= issuedAtUnixMS ||
		expiresAtUnixMS-issuedAtUnixMS > 120000 || len(signature) != ed25519.SignatureSize {
		return nil, ErrCheckpointIntegrity
	}
	var b bytes.Buffer
	b.WriteString("WDRP")
	if err := binary.Write(&b, binary.BigEndian, checkpointRevocationProofEnvelopeVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, issuedAtUnixMS); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, expiresAtUnixMS); err != nil {
		return nil, err
	}
	b.Write(signature)
	return b.Bytes(), nil
}

func decodeCheckpointRevocationAuthorizationProof(raw []byte) (checkpointRevocationProofEnvelope, error) {
	if len(raw) != checkpointRevocationProofEnvelopeSize || string(raw[:4]) != "WDRP" {
		return checkpointRevocationProofEnvelope{}, ErrCheckpointIntegrity
	}
	version := binary.BigEndian.Uint32(raw[4:8])
	issuedAt := int64(binary.BigEndian.Uint64(raw[8:16]))
	expiresAt := int64(binary.BigEndian.Uint64(raw[16:24]))
	if version != checkpointRevocationProofEnvelopeVersion || issuedAt <= 0 ||
		expiresAt <= issuedAt || expiresAt-issuedAt > 120000 {
		return checkpointRevocationProofEnvelope{}, ErrCheckpointIntegrity
	}
	return checkpointRevocationProofEnvelope{
		IssuedAtUnixMS: issuedAt, ExpiresAtUnixMS: expiresAt,
		Signature: append([]byte(nil), raw[24:]...),
	}, nil
}

// CheckpointRevocationAuthorizationMessage canonically binds the control-plane
// authorization to the exact revoke operation and its complete participant vector.
func CheckpointRevocationAuthorizationMessage(request CheckpointRevocationAuthorizationRequest) ([]byte, error) {
	if !validCheckpointEndpoint(request.Endpoint) || request.Endpoint.RevocationEpoch == ^uint64(0) ||
		request.NextEpoch != request.Endpoint.RevocationEpoch+1 ||
		len(request.OperationID) != 64 || !validLowerSHA256(request.OperationID) ||
		len(request.Participants) != 1 || request.Participants[0] != request.Endpoint ||
		request.IssuedAtUnixMS <= 0 || request.ExpiresAtUnixMS <= request.IssuedAtUnixMS ||
		request.ExpiresAtUnixMS-request.IssuedAtUnixMS > 120000 {
		return nil, ErrCheckpointIntegrity
	}
	var b bytes.Buffer
	b.WriteString("wedecent-checkpoint-revocation-authorization-v2\n")
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
	if err := putString(request.OperationID); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, request.NextEpoch); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, request.IssuedAtUnixMS); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, request.ExpiresAtUnixMS); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, uint64(len(request.Participants))); err != nil {
		return nil, err
	}
	for _, participant := range request.Participants {
		if !validCheckpointEndpoint(participant) {
			return nil, ErrCheckpointIntegrity
		}
		for _, value := range []string{participant.DeviceID, participant.AccountID, participant.OrganizationID} {
			if err := putString(value); err != nil {
				return nil, err
			}
		}
		if err := binary.Write(&b, binary.BigEndian, participant.RevocationEpoch); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func validLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
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
	if !validCheckpointFenceScope(token.Scope) ||
		(token.Action != CheckpointFenceFinalize && token.Action != CheckpointFenceRevoke) ||
		(token.Action == CheckpointFenceFinalize && token.Version != checkpointFenceVersion) ||
		(token.Action == CheckpointFenceRevoke && token.Version != checkpointFenceRevocationVersion) ||
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
		(len(token.AuthorizationProof) != 0 || token.AuthorizationProofIssuedAtUnixMS != 0 ||
			token.AuthorizationProofExpiresAtUnixMS != 0 ||
			token.ResultingRevocationEpoch != token.ExpectedRevocationEpoch) {
		return nil, ErrCheckpointStale
	}
	if token.Action == CheckpointFenceRevoke &&
		(token.ExpectedRevocationEpoch == ^uint64(0) ||
			token.ResultingRevocationEpoch != token.ExpectedRevocationEpoch+1) {
		return nil, ErrCheckpointStale
	}
	if token.Action == CheckpointFenceRevoke {
		proof, proofErr := decodeCheckpointRevocationAuthorizationProof(token.AuthorizationProof)
		if proofErr != nil || sha256.Sum256(token.AuthorizationProof) != token.AuthorizationSHA256 ||
			proof.IssuedAtUnixMS != token.AuthorizationProofIssuedAtUnixMS ||
			proof.ExpiresAtUnixMS != token.AuthorizationProofExpiresAtUnixMS ||
			proof.ExpiresAtUnixMS > token.ExpiresAtUnixMS {
			return nil, ErrCheckpointIntegrity
		}
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
	if token.Scope.Kind != "" {
		if err := putString("checkpoint-fence-scope-kind-v1"); err != nil {
			return nil, err
		}
		if err := putString(token.Scope.Kind); err != nil {
			return nil, err
		}
	}
	domain := checkpointFenceDomain
	if token.Version == checkpointFenceRevocationVersion {
		domain = checkpointFenceRevocationDomain
	}
	for _, value := range []string{
		domain, token.Scope.DeviceID, token.Scope.AccountID,
		token.Scope.OrganizationID, string(token.Action), token.OperationID,
		token.WitnessSetVersion, token.PrimaryKeyID,
	} {
		if err := putString(value); err != nil {
			return nil, err
		}
	}
	if len(token.Participants) > 0 {
		participants := append([]CheckpointEndpoint(nil), token.Participants...)
		sort.Slice(participants, func(i, j int) bool { return participants[i].DeviceID < participants[j].DeviceID })
		if err := putString("checkpoint-fence-participant-set-v1"); err != nil {
			return nil, err
		}
		if err := binary.Write(&b, binary.BigEndian, uint64(len(participants))); err != nil {
			return nil, err
		}
		for i, participant := range participants {
			if !validCheckpointEndpoint(participant) || participant.OrganizationID != token.Scope.OrganizationID ||
				(i > 0 && participants[i-1].DeviceID == participant.DeviceID) {
				return nil, ErrCheckpointIntegrity
			}
			for _, value := range []string{participant.DeviceID, participant.AccountID, participant.OrganizationID} {
				if err := putString(value); err != nil {
					return nil, err
				}
			}
			if err := binary.Write(&b, binary.BigEndian, participant.RevocationEpoch); err != nil {
				return nil, err
			}
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
	if token.Action == CheckpointFenceRevoke {
		binary.Write(&b, binary.BigEndian, token.AuthorizationProofIssuedAtUnixMS)
		binary.Write(&b, binary.BigEndian, token.AuthorizationProofExpiresAtUnixMS)
		b.Write(token.AuthorizationProof)
	}
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
	switch scope.Kind {
	case "", "device":
		return deviceIDPattern.MatchString(scope.DeviceID) &&
			canonicalUUID(scope.AccountID) && canonicalUUID(scope.OrganizationID)
	case "organization":
		return scope.DeviceID == "" && scope.AccountID == "" &&
			canonicalUUID(scope.OrganizationID)
	default:
		return false
	}
}

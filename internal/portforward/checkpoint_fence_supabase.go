package portforward

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	checkpointFenceRPCMaxBody = 1 << 20
	checkpointFenceLeaseSecs  = 60
)

// SupabaseCheckpointFenceConfig is server-only configuration. Never embed the service-role
// key or primary signing key in Local Core, a desktop renderer, or an installer.
type SupabaseCheckpointFenceConfig struct {
	Hostname          string
	Port              uint16
	SPKISHA256Pins    string
	ServiceRoleKey    string
	ActorID           string
	PrimarySigner     crypto.Signer
	CheckpointHeadKey ed25519.PublicKey
	RevocationAuthorizationKey ed25519.PublicKey
	WitnessSetVersion string
	Witnesses         []CheckpointFenceWitnessTrust
	Now               func() time.Time
}

type SupabaseCheckpointFencePrimary struct {
	endpoint          string
	actorID           string
	serviceRoleKey    string
	primarySigner     crypto.Signer
	primaryKey        ed25519.PublicKey
	checkpointHeadKey ed25519.PublicKey
	revocationAuthorizationKey ed25519.PublicKey
	witnessSetVersion string
	witnesses         map[string]ed25519.PublicKey
	witnessIDs        []string
	quorum            int
	http              *http.Client
	now               func() time.Time
}

var (
	_ CheckpointFencingPrimary     = (*SupabaseCheckpointFencePrimary)(nil)
	_ CheckpointFenceAtomicPrimary = (*SupabaseCheckpointFencePrimary)(nil)
	_ CheckpointFenceHeadReader    = (*SupabaseCheckpointFencePrimary)(nil)
	_ CheckpointAuthorityBinding   = (*SupabaseCheckpointFencePrimary)(nil)
)

type checkpointFenceEndpointWire struct {
	DeviceID        string `json:"device_id"`
	AccountID       string `json:"account_id"`
	OrganizationID  string `json:"organization_id"`
	RevocationEpoch uint64 `json:"revocation_epoch"`
}

type checkpointFenceScopeWire struct {
	Kind           string `json:"kind"`
	DeviceID       string `json:"device_id,omitempty"`
	AccountID      string `json:"account_id,omitempty"`
	OrganizationID string `json:"organization_id"`
}

type checkpointFenceTokenWire struct {
	Version                  uint32                        `json:"version"`
	Scope                    checkpointFenceScopeWire      `json:"scope"`
	Participants             []checkpointFenceEndpointWire `json:"participants"`
	ExpectedFenceGeneration  uint64                        `json:"expected_fence_generation"`
	Generation               uint64                        `json:"generation"`
	ExpectedRevocationEpoch  uint64                        `json:"expected_revocation_epoch"`
	ResultingRevocationEpoch uint64                        `json:"resulting_revocation_epoch"`
	Action                   CheckpointFenceAction         `json:"action"`
	OperationID              string                        `json:"operation_id"`
	RequestSHA256            string                        `json:"request_sha256"`
	AuthorizationSHA256      string                        `json:"authorization_sha256"`
	AuthorizationProof       string                        `json:"authorization_proof"`
	AuthorizationProofIssuedAtUnixMS int64                 `json:"authorization_proof_issued_at_unix_ms"`
	AuthorizationProofExpiresAtUnixMS int64                `json:"authorization_proof_expires_at_unix_ms"`
	PrimaryHeadGeneration    uint64                        `json:"primary_head_generation"`
	PrimaryHeadSHA256        string                        `json:"primary_head_sha256"`
	PreviousFenceSHA256      string                        `json:"previous_fence_sha256"`
	WitnessSetVersion        string                        `json:"witness_set_version"`
	WitnessIDs               []string                      `json:"witness_ids"`
	ExpiresAtUnixMS          int64                         `json:"expires_at_unix_ms"`
	PrimaryKeyID             string                        `json:"primary_key_id"`
	Signature                string                        `json:"signature"`
}

type checkpointFenceAckWire struct {
	WitnessID         string                `json:"witness_id"`
	TokenSHA256       string                `json:"token_sha256"`
	Generation        uint64                `json:"generation"`
	Action            CheckpointFenceAction `json:"action"`
	OperationID       string                `json:"operation_id"`
	WitnessKeyID      string                `json:"witness_key_id"`
	CommittedAtUnixMS int64                 `json:"committed_at_unix_ms"`
	Signature         string                `json:"signature"`
}

func NewSupabaseCheckpointFencePrimary(config SupabaseCheckpointFenceConfig) (*SupabaseCheckpointFencePrimary, error) {
	if !validCheckpointAuditAuthority(config.Hostname, config.Port) ||
		strings.TrimSpace(config.ServiceRoleKey) == "" || strings.TrimSpace(config.ServiceRoleKey) != config.ServiceRoleKey ||
		!canonicalUUID(config.ActorID) || config.PrimarySigner == nil ||
		config.WitnessSetVersion == "" || len(config.WitnessSetVersion) > 128 ||
		len(config.CheckpointHeadKey) != ed25519.PublicKeySize ||
		len(config.RevocationAuthorizationKey) != ed25519.PublicKeySize {
		return nil, ErrCheckpointUnavailable
	}
	publicKey, ok := config.PrimarySigner.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize ||
		bytes.Equal(publicKey, config.CheckpointHeadKey) ||
		bytes.Equal(publicKey, config.RevocationAuthorizationKey) ||
		bytes.Equal(config.CheckpointHeadKey, config.RevocationAuthorizationKey) {
		return nil, ErrCheckpointIntegrity
	}
	pins, err := parseCheckpointAuditPins(config.SPKISHA256Pins)
	if err != nil {
		return nil, ErrCheckpointUnavailable
	}
	quorum, err := CheckpointFenceQuorum(len(config.Witnesses))
	if err != nil {
		return nil, err
	}
	trusted := make(map[string]ed25519.PublicKey, len(config.Witnesses))
	ids := make([]string, 0, len(config.Witnesses))
	keyHashes := make(map[[sha256.Size]byte]bool, len(config.Witnesses))
	for _, witness := range config.Witnesses {
		if witness.ID == "" || len(witness.ID) > 128 || len(witness.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrCheckpointIntegrity
		}
		if _, exists := trusted[witness.ID]; exists {
			return nil, ErrCheckpointIntegrity
		}
		if bytes.Equal(witness.PublicKey, publicKey) || bytes.Equal(witness.PublicKey, config.CheckpointHeadKey) ||
			bytes.Equal(witness.PublicKey, config.RevocationAuthorizationKey) {
			return nil, ErrCheckpointIntegrity
		}
		keyHash := sha256.Sum256(witness.PublicKey)
		if keyHashes[keyHash] {
			return nil, ErrCheckpointIntegrity
		}
		keyHashes[keyHash] = true
		trusted[witness.ID] = append(ed25519.PublicKey(nil), witness.PublicKey...)
		ids = append(ids, witness.ID)
	}
	sort.Strings(ids)
	endpoint := "https://" + net.JoinHostPort(config.Hostname, fmt.Sprint(config.Port))
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host != net.JoinHostPort(config.Hostname, fmt.Sprint(config.Port)) {
		return nil, ErrCheckpointUnavailable
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, ErrCheckpointUnavailable
	}
	transport := defaultTransport.Clone()
	transport.TLSClientConfig = checkpointAuditTLSConfig(CheckpointAuditTrust{
		Hostname: config.Hostname, Port: config.Port, SPKISHA256Pins: config.SPKISHA256Pins,
	}, pins)
	httpClient := &http.Client{
		Timeout:       12 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &SupabaseCheckpointFencePrimary{
		endpoint: endpoint, actorID: config.ActorID, serviceRoleKey: config.ServiceRoleKey,
		primarySigner: config.PrimarySigner, primaryKey: append(ed25519.PublicKey(nil), publicKey...),
		checkpointHeadKey: append(ed25519.PublicKey(nil), config.CheckpointHeadKey...),
		revocationAuthorizationKey: append(ed25519.PublicKey(nil), config.RevocationAuthorizationKey...),
		witnessSetVersion: config.WitnessSetVersion, witnesses: trusted, witnessIDs: ids,
		quorum: quorum, http: httpClient, now: now,
	}, nil
}

func (p *SupabaseCheckpointFencePrimary) CheckpointAuthorityKeyID() string {
	if p == nil {
		return ""
	}
	return checkpointProviderKeyID(p.checkpointHeadKey)
}

func (p *SupabaseCheckpointFencePrimary) ReserveFence(context.Context, CheckpointFenceRequest) (CheckpointFenceToken, error) {
	return CheckpointFenceToken{}, ErrCheckpointUnavailable
}

func (p *SupabaseCheckpointFencePrimary) CommitFence(context.Context, CheckpointFenceToken, []CheckpointFenceAcknowledgement) error {
	return ErrCheckpointUnavailable
}

func (p *SupabaseCheckpointFencePrimary) ReserveFenceWithCheckpointHeads(
	ctx context.Context, request CheckpointFenceRequest, heads []CheckpointFenceParticipantHead,
) (CheckpointFenceToken, error) {
	if p == nil || ctx == nil || !validCheckpointFenceScope(request.Scope) ||
		request.Scope.Kind != "organization" || !canonicalUUID(request.Scope.OrganizationID) ||
		request.Action != CheckpointFenceFinalize && request.Action != CheckpointFenceRevoke ||
		request.OperationID == "" || len(request.OperationID) != 64 ||
		request.RequestSHA256 == ([sha256.Size]byte{}) || request.AuthorizationSHA256 == ([sha256.Size]byte{}) ||
		request.WitnessSetVersion != p.witnessSetVersion || !sameStringSet(request.WitnessIDs, p.witnessIDs) {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	if err := validateFenceParticipantHeads(heads, request.Scope, request.Participants); err != nil {
		return CheckpointFenceToken{}, err
	}
	if err := p.verifyRevocationAuthorization(request.Action, request.OperationID, request.Participants,
		request.AuthorizationProof, request.AuthorizationSHA256); err != nil {
		return CheckpointFenceToken{}, err
	}
	if request.ExpiresAtUnixMS <= p.now().UnixMilli() || request.ExpiresAtUnixMS > p.now().Add(120*time.Second).UnixMilli() {
		return CheckpointFenceToken{}, ErrCheckpointFenceExpired
	}
	headDigest, err := checkpointFenceParticipantHeadDigest(heads)
	if err != nil || headDigest != request.PrimaryHeadSHA256 {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	if request.PrimaryHeadGeneration == 0 || request.PrimaryHeadSHA256 == ([sha256.Size]byte{}) {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	participants := make([]map[string]any, 0, len(heads))
	ordered := cloneCheckpointFenceParticipantHeads(heads)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Endpoint.DeviceID < ordered[j].Endpoint.DeviceID })
	for _, item := range ordered {
		if err := VerifyCheckpointHead(item.Head, item.Endpoint, p.checkpointHeadKey); err != nil {
			return CheckpointFenceToken{}, err
		}
		participants = append(participants, map[string]any{
			"device_id":        item.Endpoint.DeviceID,
			"account_id":       item.Endpoint.AccountID,
			"organization_id":  item.Endpoint.OrganizationID,
			"revocation_epoch": item.Endpoint.RevocationEpoch,
			"head_generation":  item.Head.Generation,
			"head_hash":        hex.EncodeToString(item.Head.RecordHash[:]),
		})
	}
	args := map[string]any{
		"p_operation_id":            request.OperationID,
		"p_action":                  string(request.Action),
		"p_organization_id":         request.Scope.OrganizationID,
		"p_actor_id":                p.actorID,
		"p_request_sha256":          "\\x" + hex.EncodeToString(request.RequestSHA256[:]),
		"p_participants":            participants,
		"p_primary_head_generation": request.PrimaryHeadGeneration,
		"p_primary_head_sha256":     "\\x" + hex.EncodeToString(request.PrimaryHeadSHA256[:]),
		"p_lease_seconds":           checkpointFenceLeaseSecs,
	}
	var response map[string]json.RawMessage
	if err := p.rpc(ctx, "reserve_checkpoint_fence_operation", args, &response); err != nil {
		if operation, found, loadErr := p.LoadFence(ctx, request.Scope, request.OperationID); loadErr == nil && found {
			return operation.Token, nil
		}
		// The reservation RPC is idempotent for the exact operation fingerprint.
		if retryErr := p.rpc(ctx, "reserve_checkpoint_fence_operation", args, &response); retryErr != nil {
			return CheckpointFenceToken{}, errors.Join(ErrCheckpointAmbiguous, err, retryErr)
		}
	}
	var status string
	_ = json.Unmarshal(response["status"], &status)
	if status == "committed" {
		operation, found, loadErr := p.LoadFence(ctx, request.Scope, request.OperationID)
		if loadErr != nil || !found || !operation.Committed {
			return CheckpointFenceToken{}, errors.Join(ErrCheckpointAmbiguous, loadErr)
		}
		return operation.Token, nil
	}
	var fingerprint, fenceHash, expires string
	var fenceGeneration, revocationEpoch, primaryGeneration uint64
	var primaryHash string
	for key, target := range map[string]any{
		"fingerprint": &fingerprint, "fence_hash": &fenceHash, "fence_expires_at": &expires,
		"fence_generation": &fenceGeneration, "revocation_epoch": &revocationEpoch,
		"primary_head_generation": &primaryGeneration, "primary_head_sha256": &primaryHash,
	} {
		if raw := response[key]; len(raw) == 0 || json.Unmarshal(raw, target) != nil {
			return CheckpointFenceToken{}, ErrCheckpointIntegrity
		}
	}
	fingerprintBytes, err := decodeSHA256Hex(fingerprint)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	fenceHashBytes, err := decodeSHA256Hex(fenceHash)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	primaryHashBytes, err := decodeSHA256Hex(primaryHash)
	if err != nil || primaryGeneration != request.PrimaryHeadGeneration ||
		subtle.ConstantTimeCompare(primaryHashBytes[:], request.PrimaryHeadSHA256[:]) != 1 {
		return CheckpointFenceToken{}, ErrCheckpointStale
	}
	var expiry time.Time
	if err := json.Unmarshal(response["fence_expires_at"], &expiry); err != nil || expiry.IsZero() {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	tokenExpiry := request.ExpiresAtUnixMS
	if dbExpiry := expiry.UnixMilli(); dbExpiry < tokenExpiry {
		tokenExpiry = dbExpiry
	}
	if tokenExpiry <= p.now().UnixMilli() || request.ExpectedFenceGeneration != fenceGeneration ||
		request.ExpectedRevocationEpoch != revocationEpoch ||
		subtle.ConstantTimeCompare(fenceHashBytes[:], request.PreviousFenceSHA256[:]) != 1 {
		return CheckpointFenceToken{}, ErrCheckpointStale
	}
	canonicalParticipants := cloneCheckpointEndpoints(request.Participants)
	sort.Slice(canonicalParticipants, func(i, j int) bool { return canonicalParticipants[i].DeviceID < canonicalParticipants[j].DeviceID })
	version, err := checkpointFenceVersionForAction(request.Action)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	var proofIssuedAt, proofExpiresAt int64
	if request.Action == CheckpointFenceRevoke {
		envelope, decodeErr := decodeCheckpointRevocationAuthorizationProof(request.AuthorizationProof)
		if decodeErr != nil {
			return CheckpointFenceToken{}, ErrCheckpointIntegrity
		}
		proofIssuedAt, proofExpiresAt = envelope.IssuedAtUnixMS, envelope.ExpiresAtUnixMS
		if proofExpiresAt < tokenExpiry {
			tokenExpiry = proofExpiresAt
		}
		if tokenExpiry <= p.now().UnixMilli() {
			return CheckpointFenceToken{}, ErrCheckpointFenceExpired
		}
	}
	token := CheckpointFenceToken{
		Version:                  version,
		Scope:                    request.Scope,
		Participants:             canonicalParticipants,
		ExpectedFenceGeneration:  fenceGeneration,
		Generation:               fenceGeneration + 1,
		ExpectedRevocationEpoch:  revocationEpoch,
		ResultingRevocationEpoch: revocationEpoch + boolUint64(request.Action == CheckpointFenceRevoke),
		Action:                   request.Action, OperationID: request.OperationID,
		RequestSHA256: request.RequestSHA256, AuthorizationSHA256: request.AuthorizationSHA256,
		AuthorizationProof: append([]byte(nil), request.AuthorizationProof...),
		AuthorizationProofIssuedAtUnixMS: proofIssuedAt,
		AuthorizationProofExpiresAtUnixMS: proofExpiresAt,
		PrimaryHeadGeneration: primaryGeneration, PrimaryHeadSHA256: request.PrimaryHeadSHA256,
		PreviousFenceSHA256: fenceHashBytes,
		WitnessSetVersion:   p.witnessSetVersion, WitnessIDs: append([]string(nil), p.witnessIDs...),
		ExpiresAtUnixMS: tokenExpiry,
	}
	token, err = p.signToken(token)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	tokenDigest, err := CheckpointFenceTokenDigest(token)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	tokenWire, err := checkpointFenceTokenToWire(token)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	var recorded json.RawMessage
	recordArgs := map[string]any{
		"p_operation_id": request.OperationID,
		"p_fingerprint":  "\\x" + hex.EncodeToString(fingerprintBytes[:]),
		"p_token_sha256": "\\x" + hex.EncodeToString(tokenDigest[:]),
		"p_token":        tokenWire,
	}
	if err := p.rpc(ctx, "record_checkpoint_fence_token", recordArgs, &recorded); err != nil {
		operation, found, loadErr := p.LoadFence(ctx, request.Scope, request.OperationID)
		if loadErr == nil && found && sameCheckpointFenceToken(operation.Token, token) {
			return operation.Token, nil
		}
		// Token insertion is append-only and exact retries return the same event.
		if retryErr := p.rpc(ctx, "record_checkpoint_fence_token", recordArgs, &recorded); retryErr != nil {
			return CheckpointFenceToken{}, errors.Join(ErrCheckpointAmbiguous, err, loadErr, retryErr)
		}
	}
	return token, nil
}

func (p *SupabaseCheckpointFencePrimary) CommitFenceWithCheckpointHeads(
	ctx context.Context, token CheckpointFenceToken, acknowledgements []CheckpointFenceAcknowledgement,
	heads []CheckpointFenceParticipantHead,
) error {
	if p == nil || ctx == nil || token.Scope.Kind != "organization" ||
		verifyCheckpointFenceTokenSignature(token, p.primaryKey) != nil ||
		token.WitnessSetVersion != p.witnessSetVersion || !sameStringSet(token.WitnessIDs, p.witnessIDs) {
		return ErrCheckpointIntegrity
	}
	if token.ExpiresAtUnixMS <= p.now().UnixMilli() {
		return ErrCheckpointFenceExpired
	}
	if err := p.verifyRevocationAuthorization(token.Action, token.OperationID, token.Participants,
		token.AuthorizationProof, token.AuthorizationSHA256); err != nil {
		return err
	}
	if err := validateFenceParticipantHeads(heads, token.Scope, token.Participants); err != nil {
		return err
	}
	for _, item := range heads {
		if err := VerifyCheckpointHead(item.Head, item.Endpoint, p.checkpointHeadKey); err != nil {
			return err
		}
	}
	headDigest, err := checkpointFenceParticipantHeadDigest(heads)
	if err != nil || headDigest != token.PrimaryHeadSHA256 {
		return ErrCheckpointStale
	}
	tokenDigest, err := CheckpointFenceTokenDigest(token)
	if err != nil {
		return err
	}
	if err := p.verifyAcknowledgements(token, acknowledgements); err != nil {
		return err
	}
	fingerprint, err := p.loadOperationFingerprint(ctx, token.Scope, token.OperationID)
	if err != nil {
		return err
	}
	acks := make([]checkpointFenceAckWire, 0, len(acknowledgements))
	for _, ack := range acknowledgements {
		acks = append(acks, checkpointFenceAckToWire(ack))
	}
	var result json.RawMessage
	err = p.rpc(ctx, "commit_checkpoint_fence_operation", map[string]any{
		"p_operation_id":             token.OperationID,
		"p_fingerprint":              "\\x" + hex.EncodeToString(fingerprint[:]),
		"p_token_sha256":             "\\x" + hex.EncodeToString(tokenDigest[:]),
		"p_witness_acknowledgements": acks,
	}, &result)
	if err != nil {
		operation, found, loadErr := p.LoadFence(ctx, token.Scope, token.OperationID)
		if loadErr == nil && found && operation.Committed &&
			sameCheckpointFenceToken(operation.Token, token) &&
			p.verifyAcknowledgements(token, operation.Acknowledgements) == nil {
			return nil
		}
		return errors.Join(ErrCheckpointAmbiguous, err, loadErr)
	}
	return nil
}

func (p *SupabaseCheckpointFencePrimary) FenceHead(ctx context.Context, scope CheckpointWitnessScope) (CheckpointFenceHead, error) {
	if p == nil || ctx == nil || scope.Kind != "organization" || !canonicalUUID(scope.OrganizationID) {
		return CheckpointFenceHead{}, ErrCheckpointUnavailable
	}
	var raw json.RawMessage
	if err := p.rpc(ctx, "load_checkpoint_fence_head", map[string]any{
		"p_organization_id": scope.OrganizationID,
	}, &raw); err != nil {
		return CheckpointFenceHead{}, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return CheckpointFenceHead{}, nil
	}
	var response struct {
		Generation            uint64     `json:"generation"`
		RevocationEpoch       uint64     `json:"revocation_epoch"`
		FenceHash             string     `json:"fence_hash"`
		PrimaryHeadGeneration uint64     `json:"primary_head_generation"`
		PrimaryHeadSHA256     string     `json:"primary_head_sha256"`
		PendingOperationID    string     `json:"pending_operation_id"`
		PendingExpiresAt      *time.Time `json:"pending_expires_at"`
	}
	if err := decodeCheckpointFenceJSON(raw, &response); err != nil {
		return CheckpointFenceHead{}, ErrCheckpointIntegrity
	}
	fenceHash, err := decodeSHA256Hex(response.FenceHash)
	if err != nil {
		return CheckpointFenceHead{}, err
	}
	primaryHash, err := decodeSHA256Hex(response.PrimaryHeadSHA256)
	if err != nil {
		return CheckpointFenceHead{}, err
	}
	pendingOperationID := response.PendingOperationID
	if response.PendingExpiresAt != nil && !response.PendingExpiresAt.After(p.now()) {
		pendingOperationID = ""
	}
	return CheckpointFenceHead{
		Generation: response.Generation, RevocationEpoch: response.RevocationEpoch,
		FenceDigest: fenceHash, PrimaryHeadGeneration: response.PrimaryHeadGeneration,
		PrimaryHeadSHA256: primaryHash, PendingOperationID: pendingOperationID,
	}, nil
}

func (p *SupabaseCheckpointFencePrimary) LoadFence(
	ctx context.Context, scope CheckpointWitnessScope, operationID string,
) (CheckpointFenceOperation, bool, error) {
	if p == nil || ctx == nil || scope.Kind != "organization" || !canonicalUUID(scope.OrganizationID) ||
		len(operationID) != 64 {
		return CheckpointFenceOperation{}, false, ErrCheckpointUnavailable
	}
	var raw json.RawMessage
	if err := p.rpc(ctx, "load_checkpoint_fence_operation", map[string]any{
		"p_organization_id": scope.OrganizationID, "p_operation_id": operationID,
	}, &raw); err != nil {
		return CheckpointFenceOperation{}, false, err
	}
	var response struct {
		Found            bool                     `json:"found"`
		Token            json.RawMessage          `json:"token"`
		TokenSHA256      string                   `json:"token_sha256"`
		Fingerprint      string                   `json:"fingerprint"`
		Committed        bool                     `json:"committed"`
		Acknowledgements []checkpointFenceAckWire `json:"acknowledgements"`
	}
	if err := decodeCheckpointFenceJSON(raw, &response); err != nil {
		return CheckpointFenceOperation{}, false, ErrCheckpointIntegrity
	}
	if !response.Found {
		return CheckpointFenceOperation{}, false, nil
	}
	token, err := checkpointFenceTokenFromWire(response.Token)
	if err != nil || token.Scope != scope || token.OperationID != operationID ||
		token.WitnessSetVersion != p.witnessSetVersion || !sameStringSet(token.WitnessIDs, p.witnessIDs) ||
		verifyCheckpointFenceTokenSignature(token, p.primaryKey) != nil ||
		p.verifyRevocationAuthorizationForRecovery(token.Action, token.OperationID, token.Participants,
			token.AuthorizationProof, token.AuthorizationSHA256, response.Committed) != nil {
		return CheckpointFenceOperation{}, false, ErrCheckpointIntegrity
	}
	if !response.Committed {
		head, headErr := p.FenceHead(ctx, scope)
		if headErr != nil {
			return CheckpointFenceOperation{}, false, headErr
		}
		if head.PendingOperationID != operationID {
			return CheckpointFenceOperation{}, false, nil
		}
	}
	acks := make([]CheckpointFenceAcknowledgement, 0, len(response.Acknowledgements))
	for _, wire := range response.Acknowledgements {
		ack, err := checkpointFenceAckFromWire(wire)
		if err != nil {
			return CheckpointFenceOperation{}, false, err
		}
		acks = append(acks, ack)
	}
	operation := CheckpointFenceOperation{Token: token, Acknowledgements: acks, Committed: response.Committed}
	if response.Committed {
		if err := p.verifyAcknowledgements(token, acks); err != nil {
			return CheckpointFenceOperation{}, false, err
		}
	}
	return operation, true, nil
}


func (p *SupabaseCheckpointFencePrimary) verifyRevocationAuthorization(
	action CheckpointFenceAction, operationID string, participants []CheckpointEndpoint,
	proof []byte, authorizationHash [sha256.Size]byte,
) error {
	return p.verifyRevocationAuthorizationAt(action, operationID, participants, proof, authorizationHash, p.now().UnixMilli(), true)
}

func (p *SupabaseCheckpointFencePrimary) verifyRevocationAuthorizationForRecovery(
	action CheckpointFenceAction, operationID string, participants []CheckpointEndpoint,
	proof []byte, authorizationHash [sha256.Size]byte, committed bool,
) error {
	return p.verifyRevocationAuthorizationAt(action, operationID, participants, proof, authorizationHash, p.now().UnixMilli(), !committed)
}

func (p *SupabaseCheckpointFencePrimary) verifyRevocationAuthorizationAt(
	action CheckpointFenceAction, operationID string, participants []CheckpointEndpoint,
	proof []byte, authorizationHash [sha256.Size]byte, nowUnixMS int64, requireCurrent bool,
) error {
	if action == CheckpointFenceFinalize {
		if len(proof) != 0 {
			return ErrCheckpointIntegrity
		}
		return nil
	}
	if action != CheckpointFenceRevoke || p == nil ||
		len(p.revocationAuthorizationKey) != ed25519.PublicKeySize ||
		sha256.Sum256(proof) != authorizationHash {
		return ErrCheckpointIntegrity
	}
	envelope, err := decodeCheckpointRevocationAuthorizationProof(proof)
	if err != nil {
		return ErrCheckpointIntegrity
	}
	if requireCurrent && (envelope.IssuedAtUnixMS > nowUnixMS+30000 ||
		envelope.ExpiresAtUnixMS <= nowUnixMS) {
		return ErrCheckpointFenceExpired
	}
	if len(participants) != 1 {
		return ErrCheckpointIntegrity
	}
	endpoint := participants[0]
	if endpoint.RevocationEpoch == ^uint64(0) {
		return ErrCheckpointStale
	}
	expectedOperationID, operationErr := CheckpointRevocationOperationID(endpoint, endpoint.RevocationEpoch+1)
	if operationErr != nil || operationID != expectedOperationID {
		return ErrCheckpointIntegrity
	}
	message, err := CheckpointRevocationAuthorizationMessage(CheckpointRevocationAuthorizationRequest{
		Endpoint: endpoint, NextEpoch: endpoint.RevocationEpoch + 1,
		OperationID: operationID, Participants: participants,
		IssuedAtUnixMS: envelope.IssuedAtUnixMS, ExpiresAtUnixMS: envelope.ExpiresAtUnixMS,
	})
	if err != nil || !ed25519.Verify(p.revocationAuthorizationKey, message, envelope.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

func (p *SupabaseCheckpointFencePrimary) signToken(token CheckpointFenceToken) (CheckpointFenceToken, error) {
	token.PrimaryKeyID = checkpointProviderKeyID(p.primaryKey)
	message, err := checkpointFenceTokenMessage(token)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	signature, err := p.primarySigner.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(p.primaryKey, message, signature) {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	token.Signature = append([]byte(nil), signature...)
	return token, nil
}

func (p *SupabaseCheckpointFencePrimary) verifyAcknowledgements(
	token CheckpointFenceToken, acknowledgements []CheckpointFenceAcknowledgement,
) error {
	if p == nil || len(acknowledgements) < p.quorum || len(acknowledgements) > len(p.witnesses) {
		return ErrCheckpointQuorum
	}
	if token.WitnessSetVersion != p.witnessSetVersion || !sameStringSet(token.WitnessIDs, p.witnessIDs) {
		return ErrCheckpointIntegrity
	}
	tokenWitnesses := make(map[string]bool, len(token.WitnessIDs))
	for _, witnessID := range token.WitnessIDs {
		tokenWitnesses[witnessID] = true
	}
	digest, err := CheckpointFenceTokenDigest(token)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(acknowledgements))
	for _, ack := range acknowledgements {
		key, ok := p.witnesses[ack.WitnessID]
		if !ok || !tokenWitnesses[ack.WitnessID] || seen[ack.WitnessID] ||
			VerifyCheckpointFenceAcknowledgement(ack, ack.WitnessID, key) != nil ||
			ack.TokenSHA256 != digest || ack.Generation != token.Generation ||
			ack.Action != token.Action || ack.OperationID != token.OperationID ||
			ack.CommittedAtUnixMS > token.ExpiresAtUnixMS ||
			ack.CommittedAtUnixMS > p.now().Add(30*time.Second).UnixMilli() {
			return ErrCheckpointIntegrity
		}
		seen[ack.WitnessID] = true
	}
	if len(seen) < p.quorum {
		return ErrCheckpointQuorum
	}
	return nil
}

func (p *SupabaseCheckpointFencePrimary) loadOperationFingerprint(
	ctx context.Context, scope CheckpointWitnessScope, operationID string,
) ([sha256.Size]byte, error) {
	var raw json.RawMessage
	if err := p.rpc(ctx, "load_checkpoint_fence_operation", map[string]any{
		"p_organization_id": scope.OrganizationID, "p_operation_id": operationID,
	}, &raw); err != nil {
		return [sha256.Size]byte{}, err
	}
	var response struct {
		Found            bool                     `json:"found"`
		Token            json.RawMessage          `json:"token"`
		TokenSHA256      string                   `json:"token_sha256"`
		Fingerprint      string                   `json:"fingerprint"`
		Committed        bool                     `json:"committed"`
		Acknowledgements []checkpointFenceAckWire `json:"acknowledgements"`
	}
	if err := decodeCheckpointFenceJSON(raw, &response); err != nil || !response.Found {
		return [sha256.Size]byte{}, ErrCheckpointHistorical
	}
	return decodeSHA256Hex(response.Fingerprint)
}

func (p *SupabaseCheckpointFencePrimary) rpc(ctx context.Context, name string, args any, out any) error {
	if p == nil || ctx == nil || p.http == nil || p.endpoint == "" ||
		!validCheckpointRPCName(name) {
		return ErrCheckpointUnavailable
	}
	payload, err := json.Marshal(args)
	if err != nil || len(payload) > checkpointFenceRPCMaxBody {
		return ErrCheckpointIntegrity
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.endpoint+"/rest/v1/rpc/"+name, bytes.NewReader(payload))
	if err != nil {
		return ErrCheckpointUnavailable
	}
	request.Header.Set("apikey", p.serviceRoleKey)
	request.Header.Set("Authorization", "Bearer "+p.serviceRoleKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := p.http.Do(request)
	if err != nil {
		return errors.Join(ErrCheckpointUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		return fmt.Errorf("%w: checkpoint RPC %s returned HTTP %d: %s",
			ErrCheckpointUnavailable, name, response.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, checkpointFenceRPCMaxBody))
	if err := decoder.Decode(out); err != nil {
		return errors.Join(ErrCheckpointIntegrity, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrCheckpointIntegrity
	}
	return nil
}

func decodeCheckpointFenceJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrCheckpointIntegrity
	}
	return nil
}

func validCheckpointRPCName(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
			return false
		}
	}
	return true
}

func decodeSHA256Hex(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || strings.ToLower(value) != value {
		return result, ErrCheckpointIntegrity
	}
	copy(result[:], decoded)
	return result, nil
}

func checkpointFenceTokenToWire(token CheckpointFenceToken) (checkpointFenceTokenWire, error) {
	wire := checkpointFenceTokenWire{
		Version: token.Version,
		Scope: checkpointFenceScopeWire{
			Kind: token.Scope.Kind, DeviceID: token.Scope.DeviceID,
			AccountID: token.Scope.AccountID, OrganizationID: token.Scope.OrganizationID,
		},
		ExpectedFenceGeneration: token.ExpectedFenceGeneration, Generation: token.Generation,
		ExpectedRevocationEpoch:  token.ExpectedRevocationEpoch,
		ResultingRevocationEpoch: token.ResultingRevocationEpoch,
		Action:                   token.Action, OperationID: token.OperationID,
		RequestSHA256:         hex.EncodeToString(token.RequestSHA256[:]),
		AuthorizationSHA256:   hex.EncodeToString(token.AuthorizationSHA256[:]),
		AuthorizationProof:    base64.StdEncoding.EncodeToString(token.AuthorizationProof),
		AuthorizationProofIssuedAtUnixMS: token.AuthorizationProofIssuedAtUnixMS,
		AuthorizationProofExpiresAtUnixMS: token.AuthorizationProofExpiresAtUnixMS,
		PrimaryHeadGeneration: token.PrimaryHeadGeneration,
		PrimaryHeadSHA256:     hex.EncodeToString(token.PrimaryHeadSHA256[:]),
		PreviousFenceSHA256:   hex.EncodeToString(token.PreviousFenceSHA256[:]),
		WitnessSetVersion:     token.WitnessSetVersion, WitnessIDs: append([]string(nil), token.WitnessIDs...),
		ExpiresAtUnixMS: token.ExpiresAtUnixMS, PrimaryKeyID: token.PrimaryKeyID,
		Signature: base64.StdEncoding.EncodeToString(token.Signature),
	}
	for _, participant := range token.Participants {
		wire.Participants = append(wire.Participants, checkpointFenceEndpointWire{
			DeviceID: participant.DeviceID, AccountID: participant.AccountID,
			OrganizationID: participant.OrganizationID, RevocationEpoch: participant.RevocationEpoch,
		})
	}
	return wire, nil
}

func checkpointFenceTokenFromWire(raw json.RawMessage) (CheckpointFenceToken, error) {
	var wire checkpointFenceTokenWire
	if len(raw) == 0 || decodeCheckpointFenceJSON(raw, &wire) != nil {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	requestHash, err := decodeSHA256Hex(wire.RequestSHA256)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	authHash, err := decodeSHA256Hex(wire.AuthorizationSHA256)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	authorizationProof, err := base64.StdEncoding.Strict().DecodeString(wire.AuthorizationProof)
	if err != nil || (len(authorizationProof) != 0 && len(authorizationProof) != ed25519.SignatureSize) {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	primaryHash, err := decodeSHA256Hex(wire.PrimaryHeadSHA256)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	previousHash, err := decodeSHA256Hex(wire.PreviousFenceSHA256)
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(wire.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	token := CheckpointFenceToken{
		Version: wire.Version,
		Scope: CheckpointWitnessScope{
			Kind: wire.Scope.Kind, DeviceID: wire.Scope.DeviceID,
			AccountID: wire.Scope.AccountID, OrganizationID: wire.Scope.OrganizationID,
		},
		ExpectedFenceGeneration: wire.ExpectedFenceGeneration, Generation: wire.Generation,
		ExpectedRevocationEpoch:  wire.ExpectedRevocationEpoch,
		ResultingRevocationEpoch: wire.ResultingRevocationEpoch,
		Action:                   wire.Action, OperationID: wire.OperationID,
		RequestSHA256: requestHash, AuthorizationSHA256: authHash,
		AuthorizationProof: authorizationProof,
		AuthorizationProofIssuedAtUnixMS: wire.AuthorizationProofIssuedAtUnixMS,
		AuthorizationProofExpiresAtUnixMS: wire.AuthorizationProofExpiresAtUnixMS,
		PrimaryHeadGeneration: wire.PrimaryHeadGeneration, PrimaryHeadSHA256: primaryHash,
		PreviousFenceSHA256: previousHash,
		WitnessSetVersion:   wire.WitnessSetVersion, WitnessIDs: append([]string(nil), wire.WitnessIDs...),
		ExpiresAtUnixMS: wire.ExpiresAtUnixMS, PrimaryKeyID: wire.PrimaryKeyID,
		Signature: signature,
	}
	for _, participant := range wire.Participants {
		token.Participants = append(token.Participants, CheckpointEndpoint{
			DeviceID: participant.DeviceID, AccountID: participant.AccountID,
			OrganizationID: participant.OrganizationID, RevocationEpoch: participant.RevocationEpoch,
		})
	}
	return token, nil
}

func checkpointFenceAckToWire(ack CheckpointFenceAcknowledgement) checkpointFenceAckWire {
	return checkpointFenceAckWire{
		WitnessID: ack.WitnessID, TokenSHA256: hex.EncodeToString(ack.TokenSHA256[:]),
		Generation: ack.Generation, Action: ack.Action, OperationID: ack.OperationID,
		WitnessKeyID: ack.WitnessKeyID, CommittedAtUnixMS: ack.CommittedAtUnixMS,
		Signature: base64.StdEncoding.EncodeToString(ack.Signature),
	}
}

func checkpointFenceAckFromWire(wire checkpointFenceAckWire) (CheckpointFenceAcknowledgement, error) {
	digest, err := decodeSHA256Hex(wire.TokenSHA256)
	if err != nil {
		return CheckpointFenceAcknowledgement{}, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(wire.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return CheckpointFenceAcknowledgement{}, ErrCheckpointIntegrity
	}
	return CheckpointFenceAcknowledgement{
		WitnessID: wire.WitnessID, TokenSHA256: digest, Generation: wire.Generation,
		Action: wire.Action, OperationID: wire.OperationID, WitnessKeyID: wire.WitnessKeyID,
		CommittedAtUnixMS: wire.CommittedAtUnixMS, Signature: signature,
	}, nil
}

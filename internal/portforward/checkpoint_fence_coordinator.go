package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sort"
)

type CheckpointFenceWitnessClient struct {
	ID        string
	PublicKey ed25519.PublicKey
	Witness   CheckpointFencingWitness
}

type CheckpointFenceCoordinator struct {
	Primary           CheckpointFencingPrimary
	PrimaryKey        ed25519.PublicKey
	WitnessSetVersion string
	Witnesses         []CheckpointFenceWitnessClient
	Quorum            int
}

// Execute is retained for isolated fence-store tests and non-checkpoint use.
// Authorization lifecycle callers must use ExecuteWithCheckpointHeads.
func (c *CheckpointFenceCoordinator) Execute(ctx context.Context, request CheckpointFenceRequest) (CheckpointFenceOperation, error) {
	if c == nil || request.Scope.Kind == "organization" || len(request.Participants) != 0 {
		return CheckpointFenceOperation{}, ErrCheckpointUnavailable
	}
	return c.execute(ctx, request, nil, func() (CheckpointFenceToken, error) {
		return c.Primary.ReserveFence(ctx, request)
	}, func(token CheckpointFenceToken, acks []CheckpointFenceAcknowledgement) error {
		return c.Primary.CommitFence(ctx, token, acks)
	})
}

// ExecuteWithCheckpointHeads requires a primary adapter that atomically compares
// all authoritative checkpoint heads when reserving and committing the fence.
// A file-only fence journal is deliberately insufficient for authorization.
func (c *CheckpointFenceCoordinator) ExecuteWithCheckpointHeads(
	ctx context.Context,
	request CheckpointFenceRequest,
	heads []CheckpointFenceParticipantHead,
) (CheckpointFenceOperation, error) {
	if c == nil || ctx == nil || c.Primary == nil {
		return CheckpointFenceOperation{}, ErrCheckpointUnavailable
	}
	atomicPrimary, ok := c.Primary.(CheckpointFenceAtomicPrimary)
	if !ok || len(heads) == 0 {
		return CheckpointFenceOperation{}, ErrCheckpointUnavailable
	}
	reserve := func() (CheckpointFenceToken, error) {
		existing, found, err := c.Primary.LoadFence(ctx, request.Scope, request.OperationID)
		if err != nil {
			return CheckpointFenceToken{}, err
		}
		if found {
			if !checkpointFenceTokenMatchesOperation(existing.Token, request) {
				return CheckpointFenceToken{}, ErrCheckpointConflict
			}
			return cloneCheckpointFenceToken(existing.Token), nil
		}
		request.AuthorizationProof = append([]byte(nil), request.AuthorizationProof...)
		return atomicPrimary.ReserveFenceWithCheckpointHeads(ctx, request, cloneCheckpointFenceParticipantHeads(heads))
	}
	commit := func(token CheckpointFenceToken, acks []CheckpointFenceAcknowledgement) error {
		return atomicPrimary.CommitFenceWithCheckpointHeads(ctx, token, acks, cloneCheckpointFenceParticipantHeads(heads))
	}
	return c.execute(ctx, request, heads, reserve, commit)
}

func (c *CheckpointFenceCoordinator) execute(
	ctx context.Context,
	request CheckpointFenceRequest,
	heads []CheckpointFenceParticipantHead,
	reserve func() (CheckpointFenceToken, error),
	commit func(CheckpointFenceToken, []CheckpointFenceAcknowledgement) error,
) (CheckpointFenceOperation, error) {
	if c == nil || ctx == nil || c.Primary == nil || len(c.PrimaryKey) != ed25519.PublicKeySize ||
		c.WitnessSetVersion == "" || !validFenceCoordinatorWitnesses(c.Witnesses, c.Quorum, c.PrimaryKey) ||
		request.WitnessSetVersion != c.WitnessSetVersion ||
		!sameStringSet(request.WitnessIDs, checkpointFenceClientIDs(c.Witnesses)) {
		return CheckpointFenceOperation{}, ErrCheckpointUnavailable
	}
	if err := ctx.Err(); err != nil {
		return CheckpointFenceOperation{}, err
	}
	if request.Action == CheckpointFenceRevoke {
		if len(request.AuthorizationProof) == 0 || len(request.AuthorizationProof) > 64<<10 ||
			sha256.Sum256(request.AuthorizationProof) != request.AuthorizationSHA256 {
			return CheckpointFenceOperation{}, ErrCheckpointIntegrity
		}
	} else if len(request.AuthorizationProof) != 0 {
		return CheckpointFenceOperation{}, ErrCheckpointIntegrity
	}
	if len(heads) > 0 {
		if err := validateFenceParticipantHeads(heads, request.Scope, request.Participants); err != nil {
			return CheckpointFenceOperation{}, err
		}
	}
	token, err := reserve()
	if err != nil {
		return CheckpointFenceOperation{}, err
	}
	if err := verifyCheckpointFenceTokenSignature(token, c.PrimaryKey); err != nil ||
		!checkpointFenceTokenMatchesRequest(token, request) {
		return CheckpointFenceOperation{}, ErrCheckpointIntegrity
	}
	if existing, found, loadErr := c.Primary.LoadFence(ctx, token.Scope, token.OperationID); loadErr != nil {
		return CheckpointFenceOperation{}, errors.Join(ErrCheckpointAmbiguous, loadErr)
	} else if found && existing.Committed {
		if err := c.verifyCommittedOperation(existing, token); err != nil {
			return CheckpointFenceOperation{}, err
		}
		return existing, nil
	}

	byID := make(map[string]CheckpointFenceWitnessClient, len(c.Witnesses))
	for _, witness := range c.Witnesses {
		byID[witness.ID] = witness
	}
	type result struct {
		ack CheckpointFenceAcknowledgement
		id  string
		err error
	}
	responses := make(chan result, len(c.Witnesses))
	for _, witness := range c.Witnesses {
		witness := witness
		go func() {
			ack, err := witness.Witness.CommitFence(ctx, token)
			responses <- result{ack: ack, id: witness.ID, err: err}
		}()
	}
	acks := make([]CheckpointFenceAcknowledgement, 0, len(c.Witnesses))
	seen := make(map[string]bool, len(c.Witnesses))
	for received := 0; received < len(c.Witnesses) && len(acks) < c.Quorum; received++ {
		select {
		case <-ctx.Done():
			return CheckpointFenceOperation{}, errors.Join(ErrCheckpointQuorum, ctx.Err())
		case response := <-responses:
			trust, ok := byID[response.id]
			if !ok {
				return CheckpointFenceOperation{}, ErrCheckpointIntegrity
			}
			if response.err != nil {
				if errors.Is(response.err, ErrCheckpointFenceExpired) {
					continue
				}
				if errors.Is(response.err, ErrCheckpointConflict) || errors.Is(response.err, ErrCheckpointStale) {
					return CheckpointFenceOperation{}, ErrCheckpointWitnessDisagreement
				}
				if errors.Is(response.err, ErrCheckpointIntegrity) {
					return CheckpointFenceOperation{}, ErrCheckpointIntegrity
				}
				continue
			}
			if VerifyCheckpointFenceAcknowledgement(response.ack, response.id, trust.PublicKey) != nil {
				return CheckpointFenceOperation{}, ErrCheckpointIntegrity
			}
			digest, digestErr := CheckpointFenceTokenDigest(token)
			if digestErr != nil {
				return CheckpointFenceOperation{}, digestErr
			}
			if seen[response.id] || response.ack.TokenSHA256 != digest ||
				response.ack.Generation != token.Generation || response.ack.Action != token.Action ||
				response.ack.OperationID != token.OperationID ||
				response.ack.CommittedAtUnixMS > token.ExpiresAtUnixMS {
				return CheckpointFenceOperation{}, ErrCheckpointWitnessDisagreement
			}
			seen[response.id] = true
			acks = append(acks, cloneCheckpointFenceAck(response.ack))
		}
	}
	if len(acks) < c.Quorum {
		return CheckpointFenceOperation{}, ErrCheckpointQuorum
	}
	if err := commit(token, acks); err != nil {
		operation, found, loadErr := c.Primary.LoadFence(ctx, token.Scope, token.OperationID)
		if loadErr == nil && found && operation.Committed {
			if verifyErr := c.verifyCommittedOperation(operation, token); verifyErr == nil {
				return operation, nil
			}
		}
		return CheckpointFenceOperation{}, errors.Join(ErrCheckpointAmbiguous, err, loadErr)
	}
	operation, found, err := c.Primary.LoadFence(ctx, token.Scope, token.OperationID)
	if err != nil {
		return CheckpointFenceOperation{}, errors.Join(ErrCheckpointAmbiguous, err)
	}
	if !found || !operation.Committed {
		return CheckpointFenceOperation{}, ErrCheckpointAmbiguous
	}
	if err := c.verifyCommittedOperation(operation, token); err != nil {
		return CheckpointFenceOperation{}, err
	}
	return operation, nil
}

func (c *CheckpointFenceCoordinator) verifyCommittedOperation(operation CheckpointFenceOperation, token CheckpointFenceToken) error {
	if !operation.Committed || !sameCheckpointFenceToken(operation.Token, token) {
		return ErrCheckpointIntegrity
	}
	byID := make(map[string]ed25519.PublicKey, len(c.Witnesses))
	for _, witness := range c.Witnesses {
		byID[witness.ID] = witness.PublicKey
	}
	seen := make(map[string]bool, len(operation.Acknowledgements))
	digest, err := CheckpointFenceTokenDigest(token)
	if err != nil {
		return err
	}
	for _, ack := range operation.Acknowledgements {
		key, ok := byID[ack.WitnessID]
		if !ok || seen[ack.WitnessID] || VerifyCheckpointFenceAcknowledgement(ack, ack.WitnessID, key) != nil ||
			ack.TokenSHA256 != digest || ack.Generation != token.Generation || ack.Action != token.Action ||
			ack.OperationID != token.OperationID || ack.CommittedAtUnixMS > token.ExpiresAtUnixMS {
			return ErrCheckpointIntegrity
		}
		seen[ack.WitnessID] = true
	}
	if len(seen) < c.Quorum {
		return ErrCheckpointQuorum
	}
	return nil
}

func checkpointFenceTokenMatchesOperation(token CheckpointFenceToken, request CheckpointFenceRequest) bool {
	return token.Scope == request.Scope && token.Action == request.Action &&
		token.OperationID == request.OperationID && token.RequestSHA256 == request.RequestSHA256 &&
		token.AuthorizationSHA256 == request.AuthorizationSHA256 &&
		token.WitnessSetVersion == request.WitnessSetVersion &&
		sameStringSet(token.WitnessIDs, request.WitnessIDs) &&
		sameCheckpointEndpointSet(token.Participants, request.Participants)
}

func checkpointFenceTokenMatchesRequest(token CheckpointFenceToken, request CheckpointFenceRequest) bool {
	return token.Scope == request.Scope && token.Action == request.Action &&
		token.OperationID == request.OperationID && token.RequestSHA256 == request.RequestSHA256 &&
		token.AuthorizationSHA256 == request.AuthorizationSHA256 &&
		token.ExpectedRevocationEpoch == request.ExpectedRevocationEpoch &&
		token.ResultingRevocationEpoch == request.ExpectedRevocationEpoch+boolUint64(request.Action == CheckpointFenceRevoke) &&
		token.WitnessSetVersion == request.WitnessSetVersion &&
		sameStringSet(token.WitnessIDs, request.WitnessIDs) &&
		sameCheckpointEndpointSet(token.Participants, request.Participants) &&
		(request.ExpectedFenceGeneration == 0 || token.ExpectedFenceGeneration == request.ExpectedFenceGeneration) &&
		(request.PrimaryHeadGeneration == 0 || token.PrimaryHeadGeneration == request.PrimaryHeadGeneration) &&
		(request.PrimaryHeadSHA256 == ([sha256.Size]byte{}) || token.PrimaryHeadSHA256 == request.PrimaryHeadSHA256) &&
		(request.PreviousFenceSHA256 == ([sha256.Size]byte{}) || token.PreviousFenceSHA256 == request.PreviousFenceSHA256)
}

func boolUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func cloneCheckpointFenceParticipantHeads(heads []CheckpointFenceParticipantHead) []CheckpointFenceParticipantHead {
	out := make([]CheckpointFenceParticipantHead, len(heads))
	for i, item := range heads {
		item.Head.Signature = append([]byte(nil), item.Head.Signature...)
		out[i] = item
	}
	return out
}

func cloneCheckpointEndpoints(endpoints []CheckpointEndpoint) []CheckpointEndpoint {
	return append([]CheckpointEndpoint(nil), endpoints...)
}

func sameCheckpointEndpointSet(a, b []CheckpointEndpoint) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := cloneCheckpointEndpoints(a), cloneCheckpointEndpoints(b)
	sort.Slice(left, func(i, j int) bool { return left[i].DeviceID < left[j].DeviceID })
	sort.Slice(right, func(i, j int) bool { return right[i].DeviceID < right[j].DeviceID })
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func fenceHeadEndpoints(heads []CheckpointFenceParticipantHead) []CheckpointEndpoint {
	endpoints := make([]CheckpointEndpoint, len(heads))
	for i, head := range heads {
		endpoints[i] = head.Endpoint
	}
	return endpoints
}

func validateFenceParticipantHeads(heads []CheckpointFenceParticipantHead, scope CheckpointWitnessScope, participants []CheckpointEndpoint) error {
	if len(heads) == 0 || !sameCheckpointEndpointSet(fenceHeadEndpoints(heads), participants) {
		return ErrCheckpointIntegrity
	}
	seen := make(map[CheckpointWitnessScope]bool, len(heads))
	for _, item := range heads {
		if !validCheckpointEndpoint(item.Endpoint) ||
			item.Endpoint.OrganizationID != scope.OrganizationID ||
			item.Head.DeviceID != item.Endpoint.DeviceID ||
			item.Head.AccountID != item.Endpoint.AccountID ||
			item.Head.OrganizationID != item.Endpoint.OrganizationID ||
			seen[witnessScope(item.Endpoint)] {
			return ErrCheckpointIntegrity
		}
		seen[witnessScope(item.Endpoint)] = true
	}
	return nil
}

func validFenceCoordinatorWitnesses(witnesses []CheckpointFenceWitnessClient, quorum int, primaryKey ed25519.PublicKey) bool {
	expected, err := CheckpointFenceQuorum(len(witnesses))
	if err != nil || quorum != expected || len(primaryKey) != ed25519.PublicKeySize {
		return false
	}
	ids := make(map[string]bool, len(witnesses))
	keys := make(map[[32]byte]bool, len(witnesses))
	for _, witness := range witnesses {
		if witness.ID == "" || witness.Witness == nil || len(witness.PublicKey) != ed25519.PublicKeySize || ids[witness.ID] {
			return false
		}
		if bytes.Equal(witness.PublicKey, primaryKey) {
			return false
		}
		ids[witness.ID] = true
		keyHash := sha256.Sum256(witness.PublicKey)
		if keys[keyHash] {
			return false
		}
		keys[keyHash] = true
	}
	return true
}

func checkpointFenceClientIDs(witnesses []CheckpointFenceWitnessClient) []string {
	ids := make([]string, len(witnesses))
	for i, witness := range witnesses {
		ids[i] = witness.ID
	}
	return ids
}

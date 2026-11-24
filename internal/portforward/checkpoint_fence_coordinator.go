package portforward

import (
	"context"
	"crypto/ed25519"
	"bytes"
	"crypto/sha256"
	"errors"
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

// Execute reserves the exact operation before asking witnesses to persist it.
// A quorum is committed by the primary only after each acknowledgement verifies.
// A partial quorum leaves the reservation pending for exact retry/recovery.
func (c *CheckpointFenceCoordinator) Execute(ctx context.Context, request CheckpointFenceRequest) (CheckpointFenceOperation, error) {
	if c == nil || ctx == nil || c.Primary == nil || len(c.PrimaryKey) != ed25519.PublicKeySize ||
		c.WitnessSetVersion == "" || !validFenceCoordinatorWitnesses(c.Witnesses, c.Quorum, c.PrimaryKey) ||
		request.WitnessSetVersion != c.WitnessSetVersion ||
		!sameStringSet(request.WitnessIDs, checkpointFenceClientIDs(c.Witnesses)) {
		return CheckpointFenceOperation{}, ErrCheckpointUnavailable
	}
	token, err := c.Primary.ReserveFence(ctx, request)
	if err != nil {
		return CheckpointFenceOperation{}, err
	}
	if err := verifyCheckpointFenceTokenSignature(token, c.PrimaryKey); err != nil ||
		token.Scope != request.Scope || token.OperationID != request.OperationID {
		return CheckpointFenceOperation{}, ErrCheckpointIntegrity
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
			if response.err != nil || !ok || seen[response.id] ||
				VerifyCheckpointFenceAcknowledgement(response.ack, response.id, trust.PublicKey) != nil {
				continue
			}
			digest, digestErr := CheckpointFenceTokenDigest(token)
			if digestErr != nil || response.ack.TokenSHA256 != digest ||
				response.ack.Generation != token.Generation || response.ack.Action != token.Action ||
				response.ack.OperationID != token.OperationID ||
				response.ack.CommittedAtUnixMS > token.ExpiresAtUnixMS {
				continue
			}
			seen[response.id] = true
			acks = append(acks, cloneCheckpointFenceAck(response.ack))
		}
	}
	if len(acks) < c.Quorum {
		return CheckpointFenceOperation{}, ErrCheckpointQuorum
	}
	if err := c.Primary.CommitFence(ctx, token, acks); err != nil {
		operation, found, loadErr := c.Primary.LoadFence(ctx, token.Scope, token.OperationID)
		if loadErr == nil && found && operation.Committed && sameFenceToken(operation.Token, token) {
			return operation, nil
		}
		return CheckpointFenceOperation{}, errors.Join(ErrCheckpointAmbiguous, err, loadErr)
	}
	operation, found, err := c.Primary.LoadFence(ctx, token.Scope, token.OperationID)
	if err != nil {
		return CheckpointFenceOperation{}, errors.Join(ErrCheckpointAmbiguous, err)
	}
	if !found || !operation.Committed || !sameFenceToken(operation.Token, token) {
		return CheckpointFenceOperation{}, ErrCheckpointAmbiguous
	}
	return operation, nil
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

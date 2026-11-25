package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"sync"
	"time"
)

var (
	ErrCheckpointQuorum              = errors.New("portforward: independent checkpoint witness quorum unavailable")
	ErrCheckpointWitnessDisagreement = errors.New("portforward: independent checkpoint witnesses disagree")
	ErrCheckpointWitnessRollback     = errors.New("portforward: historical checkpoint head rejected by witness")
)

type CheckpointWitnessScope struct {
	Kind           string
	DeviceID       string
	AccountID      string
	OrganizationID string
}

type CheckpointWitnessReceipt struct {
	WitnessID            string
	Scope                CheckpointWitnessScope
	Kind                 string
	Generation           uint64
	PreviousHash         [sha256.Size]byte
	RecordHash           [sha256.Size]byte
	PrimaryGeneration    uint64
	PrimaryHead          [sha256.Size]byte
	PrimaryReceiptSHA256 [sha256.Size]byte
	RequestSHA256        [sha256.Size]byte
	JTI                  string
	AuthorizationSHA256  [sha256.Size]byte
	RevocationEpoch      uint64
	ProviderKeyID        string
	WitnessKeyID         string
	Signature            []byte
}

type CheckpointWitnessAck struct {
	WitnessID            string
	Scope                CheckpointWitnessScope
	JTI                  string
	RequestSHA256        [sha256.Size]byte
	PrimaryReceiptSHA256 [sha256.Size]byte
	Decision             string
	Status               string
	WitnessKeyID         string
	Signature            []byte
}

type CheckpointWitnessHead struct {
	WitnessID         string
	Scope             CheckpointWitnessScope
	Generation        uint64
	RecordHash        [sha256.Size]byte
	PrimaryGeneration uint64
	PrimaryHead       [sha256.Size]byte
	RevocationEpoch   uint64
	WitnessKeyID      string
	Signature         []byte
}

type ReplayCheckpointRecoveryProvider interface {
	Recover(context.Context, CheckpointRequest) (CheckpointResult, error)
}

type CheckpointWitness interface {
	Commit(context.Context, CheckpointRequest, CheckpointReceipt) (CheckpointWitnessReceipt, error)
	Revoke(context.Context, CheckpointEndpoint, uint64) (CheckpointWitnessReceipt, error)
	Acknowledge(context.Context, CheckpointRequest, CheckpointReceipt) (CheckpointWitnessAck, error)
	Head(context.Context, CheckpointWitnessScope) (CheckpointWitnessHead, error)
}

type CheckpointWitnessTrust struct {
	Witness   CheckpointWitness
	ID        string
	PublicKey ed25519.PublicKey
}

// WitnessedReplayCheckpointProvider requires independent witness quorum for every
// consume and revocation. Pending must be durable and local; it is not authority.
// CheckpointFinalizationAuditSink must deduplicate its externally visible effect
// by operationID. The same ID is retried if a process crashes before the local
// completion marker is durable.
type CheckpointFinalizationAuditSink func(context.Context, string, CheckpointFinalizationEvidence) error

// CheckpointRevocationProofProvider supplies the signed revocation envelope.
// The atomic primary independently validates it and binds its digest to the fence.
type CheckpointRevocationProofProvider interface {
	CheckpointRevocationProof(context.Context, CheckpointRevocationAuthorizationRequest) ([]byte, error)
}

type CheckpointFinalizationEvidence struct {
	PrimaryReceipt          CheckpointReceipt
	WitnessAcknowledgements []CheckpointWitnessAck
	RevocationProofs        []CheckpointFinalizationRevocationProof
}

type CheckpointFinalizationRevocationProof struct {
	PrimaryHead  CheckpointHead
	WitnessHeads []CheckpointWitnessHead
}

type WitnessedReplayCheckpointProvider struct {
	Primary          ReplayCheckpointProvider
	PrimaryKey       ed25519.PublicKey
	Witnesses        []CheckpointWitnessTrust
	Quorum           int
	Pending          CheckpointPendingStore
	Fencing          *CheckpointFenceCoordinator
	RevocationProofs CheckpointRevocationProofProvider
}

func validIndependentFenceTrust(primaryKey ed25519.PublicKey, witnesses []CheckpointWitnessTrust, coordinator *CheckpointFenceCoordinator) bool {
	if coordinator == nil || len(primaryKey) != ed25519.PublicKeySize ||
		len(coordinator.PrimaryKey) != ed25519.PublicKeySize {
		return false
	}
	seen := make(map[[sha256.Size]byte]bool, len(witnesses)+len(coordinator.Witnesses)+2)
	add := func(key ed25519.PublicKey) bool {
		if len(key) != ed25519.PublicKeySize {
			return false
		}
		digest := sha256.Sum256(key)
		if seen[digest] {
			return false
		}
		seen[digest] = true
		return true
	}
	if !add(primaryKey) || !add(coordinator.PrimaryKey) {
		return false
	}
	for _, witness := range witnesses {
		if !add(witness.PublicKey) {
			return false
		}
	}
	for _, witness := range coordinator.Witnesses {
		if !add(witness.PublicKey) {
			return false
		}
	}
	return true
}

func (p *WitnessedReplayCheckpointProvider) ValidateConfiguration() error {
	if p == nil || p.Primary == nil || p.Pending == nil || p.Fencing == nil || p.RevocationProofs == nil ||
		!validWitnessConfiguration(p.Witnesses, p.Quorum, p.PrimaryKey) ||
		p.Fencing.Primary == nil || p.Fencing.WitnessSetVersion == "" ||
		!validFenceCoordinatorWitnesses(p.Fencing.Witnesses, p.Fencing.Quorum, p.Fencing.PrimaryKey) ||
		!validIndependentFenceTrust(p.PrimaryKey, p.Witnesses, p.Fencing) {
		return ErrCheckpointUnavailable
	}
	if _, ok := p.Fencing.Primary.(CheckpointFenceAtomicPrimary); !ok {
		return ErrCheckpointUnavailable
	}
	if _, ok := p.Fencing.Primary.(CheckpointFenceHeadReader); !ok {
		return ErrCheckpointUnavailable
	}
	replayBinding, replayOK := p.Primary.(CheckpointAuthorityBinding)
	fenceBinding, fenceOK := p.Fencing.Primary.(CheckpointAuthorityBinding)
	if !replayOK || !fenceOK || replayBinding.CheckpointAuthorityKeyID() == "" ||
		replayBinding.CheckpointAuthorityKeyID() != fenceBinding.CheckpointAuthorityKeyID() {
		return ErrCheckpointUnavailable
	}
	trustConfigurer, ok := p.Pending.(checkpointPendingTrustConfigurer)
	if !ok {
		return ErrCheckpointUnavailable
	}
	if err := trustConfigurer.SetCheckpointTrustAnchors(p.PrimaryKey, p.Witnesses, p.Quorum); err != nil {
		return errors.Join(ErrCheckpointIntegrity, err)
	}
	return nil
}

func (p *WitnessedReplayCheckpointProvider) Consume(ctx context.Context, request CheckpointRequest) (result CheckpointResult, resultErr error) {
	if err := p.ValidateConfiguration(); err != nil {
		return CheckpointResult{}, err
	}
	locker, ok := p.Pending.(checkpointPendingFinalizationLocker)
	if !ok {
		return CheckpointResult{}, ErrCheckpointUnavailable
	}
	unlock, err := locker.LockFinalization(ctx, request)
	if err != nil {
		return CheckpointResult{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, unlock())
	}()
	existingPending, err := p.Pending.Begin(ctx, request)
	if err != nil {
		return CheckpointResult{}, err
	}
	result, err = p.Primary.Consume(ctx, request)
	if err != nil {
		return CheckpointResult{}, err
	}
	if err := VerifyCheckpointResult(result, request, p.PrimaryKey); err != nil {
		return CheckpointResult{}, err
	}
	if result.Disposition == CheckpointRecovered && !existingPending {
		return CheckpointResult{}, ErrCheckpointHistorical
	}
	ackStore, ok := p.Pending.(checkpointPendingAcknowledgements)
	if !ok {
		return CheckpointResult{}, ErrCheckpointUnavailable
	}
	// A resolved journal entry is past witness commitment. Resume only the
	// acknowledgement/compaction tail; never issue another witness commit.
	_, finalizationErr := ackStore.LoadAcknowledgements(ctx, request, result.CheckpointReceipt, p.Witnesses)
	var receipts []CheckpointWitnessReceipt
	if errors.Is(finalizationErr, ErrCheckpointHistorical) {
		receipts, err = p.commitWitnessQuorum(ctx, request, result.CheckpointReceipt, existingPending, result.Disposition)
		if err != nil {
			return CheckpointResult{}, err
		}
	} else if finalizationErr != nil {
		return CheckpointResult{}, finalizationErr
	}
	if err := p.Pending.Resolve(ctx, request, result.CheckpointReceipt); err != nil {
		return CheckpointResult{}, err
	}
	acks, err := p.acknowledgeWitnessQuorumLocked(ctx, request, result.CheckpointReceipt, ackStore)
	if err != nil {
		return CheckpointResult{}, err
	}
	compactor, ok := p.Pending.(checkpointPendingCompactor)
	if !ok {
		return CheckpointResult{}, ErrCheckpointUnavailable
	}
	if err := compactor.Compact(ctx, acks, p.Witnesses, p.Quorum); err != nil {
		return CheckpointResult{}, errors.Join(ErrCheckpointUnavailable, err)
	}
	if _, err := p.executeFinalizationFence(ctx, request, result.CheckpointReceipt); err != nil {
		return CheckpointResult{}, err
	}
	result.WitnessReceipts = receipts
	result.WitnessAcknowledgements = acks
	if result.Disposition == CheckpointRecovered {
		return CheckpointResult{}, ErrCheckpointHistorical
	}
	return result, nil
}

func (p *WitnessedReplayCheckpointProvider) Finalize(ctx context.Context, request CheckpointRequest) error {
	return p.FinalizeWithAudit(ctx, request, nil)
}

// FinalizeWithAudit invokes an idempotent audit sink with a stable operation ID.
// The sink must deduplicate effects by that ID because a crash can occur after the
// sink commits but before the local completion marker is persisted.
func (p *WitnessedReplayCheckpointProvider) FinalizeWithAudit(ctx context.Context, request CheckpointRequest, onQuorumCommitted CheckpointFinalizationAuditSink) (resultErr error) {
	if p == nil {
		return ErrCheckpointUnavailable
	}
	locker, ok := p.Pending.(checkpointPendingFinalizationLocker)
	if !ok {
		return ErrCheckpointUnavailable
	}
	unlock, err := locker.LockFinalization(ctx, request)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, unlock())
	}()

	if err := p.ValidateConfiguration(); err != nil {
		return err
	}
	store, ok := p.Pending.(interface {
		LoadFinalization(context.Context, string, string, [sha256.Size]byte) (CheckpointRequest, CheckpointReceipt, bool, bool, error)
	})
	if !ok {
		return ErrCheckpointUnavailable
	}
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return err
	}
	saved, receipt, found, hasReceipt, err := store.LoadFinalization(ctx, request.ConsumingDeviceID, request.JTI, request.AuthorizationSHA256)
	if err != nil {
		return err
	}
	if !found {
		return ErrCheckpointHistorical
	}
	savedFingerprint, err := CheckpointRequestFingerprint(saved)
	if err != nil || savedFingerprint != fingerprint {
		return ErrCheckpointConflict
	}
	if !hasReceipt {
		recoverer, ok := p.Primary.(ReplayCheckpointRecoveryProvider)
		if !ok {
			return ErrCheckpointAmbiguous
		}
		result, err := recoverer.Recover(ctx, saved)
		if err != nil {
			return errors.Join(ErrCheckpointAmbiguous, err)
		}
		if result.Disposition != CheckpointRecovered || VerifyCheckpointResult(result, saved, p.PrimaryKey) != nil {
			return ErrCheckpointIntegrity
		}
		receipt = cloneCheckpointReceiptValue(result.CheckpointReceipt)
		if err := p.Pending.Resolve(ctx, saved, receipt); err != nil {
			return errors.Join(ErrCheckpointUnavailable, err)
		}
	}
	if err := VerifyCheckpointReceipt(receipt, saved, p.PrimaryKey); err != nil {
		return err
	}
	completionStore, ok := p.Pending.(checkpointPendingCompletionStore)
	if !ok {
		return ErrCheckpointUnavailable
	}
	operationID, err := checkpointFinalizationID(saved, receipt)
	if err != nil {
		return err
	}
	completed, err := completionStore.LoadFinalizationComplete(ctx, saved, receipt, operationID)
	if err != nil {
		return err
	}

	var evidenceStore checkpointPendingEvidenceStore
	var persistedEvidence CheckpointFinalizationEvidence
	var hasPersistedEvidence bool
	var acks []CheckpointWitnessAck
	fenceCommitted := false
	if onQuorumCommitted != nil {
		evidenceStore, ok = p.Pending.(checkpointPendingEvidenceStore)
		if !ok {
			return ErrCheckpointUnavailable
		}
		persistedEvidence, hasPersistedEvidence, err = evidenceStore.LoadFinalizationEvidence(ctx, saved, receipt, operationID)
		if err != nil {
			return err
		}
		if hasPersistedEvidence {
			acks = append([]CheckpointWitnessAck(nil), persistedEvidence.WitnessAcknowledgements...)
		}
		// Once proof bytes have been durably frozen, retries must submit those
		// exact bytes. Re-reading mutable provider heads here would change the
		// evidence after an ambiguous external commit.
		if hasPersistedEvidence && !completed {
			if _, err := p.executeFinalizationFence(ctx, saved, receipt); err != nil {
				return err
			}
			fenceCommitted = true
			if err := onQuorumCommitted(ctx, operationID, persistedEvidence); err != nil {
				return err
			}
			if err := completionStore.MarkFinalizationComplete(ctx, saved, receipt, operationID); err != nil {
				return errors.Join(ErrCheckpointUnavailable, err)
			}
			completed = true
		}
	}

	if !hasPersistedEvidence || onQuorumCommitted == nil {
		ackStore, ok := p.Pending.(checkpointPendingAcknowledgements)
		if !ok {
			return ErrCheckpointUnavailable
		}
		acks, err = p.acknowledgeWitnessQuorumLocked(ctx, saved, receipt, ackStore)
		if err != nil {
			return errors.Join(ErrCheckpointQuorum, err)
		}
		if committedCheckpointAckCount(acks) < p.Quorum {
			return ErrCheckpointQuorum
		}
		if err := p.verifyRequestMembershipVector(ctx, saved); err != nil {
			return err
		}
		if _, err := p.executeFinalizationFence(ctx, saved, receipt); err != nil {
			return err
		}
		fenceCommitted = true
		if onQuorumCommitted != nil && !completed {
			evidence, err := p.finalizationEvidence(ctx, saved, receipt, acks)
			if err != nil {
				return err
			}
			if err := evidenceStore.StoreFinalizationEvidence(ctx, saved, receipt, operationID, evidence); err != nil {
				return errors.Join(ErrCheckpointUnavailable, err)
			}
			persistedEvidence, hasPersistedEvidence, err = evidenceStore.LoadFinalizationEvidence(ctx, saved, receipt, operationID)
			if err != nil || !hasPersistedEvidence {
				return errors.Join(ErrCheckpointIntegrity, err)
			}
			if err := onQuorumCommitted(ctx, operationID, persistedEvidence); err != nil {
				return err
			}
			if err := completionStore.MarkFinalizationComplete(ctx, saved, receipt, operationID); err != nil {
				return errors.Join(ErrCheckpointUnavailable, err)
			}
		}
	}
	if !fenceCommitted {
		if _, err := p.executeFinalizationFence(ctx, saved, receipt); err != nil {
			return err
		}
	}
	compactor, ok := p.Pending.(checkpointPendingCompactor)
	if !ok {
		return ErrCheckpointUnavailable
	}
	if err := compactor.Compact(ctx, acks, p.Witnesses, p.Quorum); err != nil {
		return errors.Join(ErrCheckpointUnavailable, err)
	}
	return nil
}
func (p *WitnessedReplayCheckpointProvider) finalizationEvidence(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, acknowledgements []CheckpointWitnessAck) (CheckpointFinalizationEvidence, error) {
	if p == nil || ctx == nil || VerifyCheckpointReceipt(receipt, request, p.PrimaryKey) != nil {
		return CheckpointFinalizationEvidence{}, ErrCheckpointIntegrity
	}
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return CheckpointFinalizationEvidence{}, err
	}
	seen := make(map[string]bool, len(acknowledgements))
	validAcks := make([]CheckpointWitnessAck, 0, len(acknowledgements))
	for _, ack := range acknowledgements {
		var trust *CheckpointWitnessTrust
		for i := range p.Witnesses {
			if p.Witnesses[i].ID == ack.WitnessID {
				trust = &p.Witnesses[i]
				break
			}
		}
		if trust == nil || seen[ack.WitnessID] || ack.Decision != "committed" ||
			VerifyCheckpointWitnessAck(ack, trust.ID, trust.PublicKey) != nil ||
			!checkpointAckMatchesOperation(ack, request, receipt) ||
			ack.RequestSHA256 != fingerprint {
			continue
		}
		seen[ack.WitnessID] = true
		validAcks = append(validAcks, ack)
	}
	if len(validAcks) < p.Quorum {
		return CheckpointFinalizationEvidence{}, ErrCheckpointQuorum
	}

	evidence := CheckpointFinalizationEvidence{
		PrimaryReceipt:          cloneCheckpointReceiptValue(receipt),
		WitnessAcknowledgements: validAcks,
		RevocationProofs:        make([]CheckpointFinalizationRevocationProof, 0, len(checkpointRequestParticipants(request))),
	}
	for _, endpoint := range checkpointRequestParticipants(request) {
		primary, err := p.Primary.Head(ctx, endpoint)
		if err != nil {
			return CheckpointFinalizationEvidence{}, err
		}
		if err := VerifyCheckpointHead(primary, endpoint, p.PrimaryKey); err != nil ||
			primary.RevocationEpoch != endpoint.RevocationEpoch {
			return CheckpointFinalizationEvidence{}, errors.Join(ErrCheckpointRevoked, err)
		}
		proof := CheckpointFinalizationRevocationProof{PrimaryHead: primary}
		headIDs := make(map[string]bool, len(p.Witnesses))
		for _, trust := range p.Witnesses {
			head, err := trust.Witness.Head(ctx, witnessScope(endpoint))
			if err != nil || VerifyCheckpointWitnessHead(head, trust.ID, trust.PublicKey) != nil ||
				head.Scope != witnessScope(endpoint) || headIDs[head.WitnessID] ||
				head.PrimaryGeneration != primary.Generation || head.PrimaryHead != primary.RecordHash ||
				head.RevocationEpoch != primary.RevocationEpoch {
				continue
			}
			headIDs[head.WitnessID] = true
			proof.WitnessHeads = append(proof.WitnessHeads, head)
		}
		if len(proof.WitnessHeads) < p.Quorum {
			return CheckpointFinalizationEvidence{}, ErrCheckpointQuorum
		}
		evidence.RevocationProofs = append(evidence.RevocationProofs, proof)
	}
	return evidence, nil
}

func (p *WitnessedReplayCheckpointProvider) Revoke(ctx context.Context, endpoint CheckpointEndpoint, next uint64) (resultErr error) {
	if err := p.ValidateConfiguration(); err != nil {
		return err
	}
	if !validCheckpointEndpoint(endpoint) || endpoint.RevocationEpoch == ^uint64(0) || next != endpoint.RevocationEpoch+1 {
		return ErrCheckpointStale
	}
	locker, ok := p.Pending.(checkpointPendingTransitionLocker)
	if !ok {
		return ErrCheckpointUnavailable
	}
	unlock, err := locker.LockTransition(ctx)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, unlock())
	}()
	operationID, err := CheckpointRevocationOperationID(endpoint, next)
	if err != nil {
		return err
	}
	proofRequest := CheckpointRevocationAuthorizationRequest{
		Endpoint: endpoint, NextEpoch: next, OperationID: operationID,
		Participants: []CheckpointEndpoint{endpoint},
	}
	authorizationProof, err := p.RevocationProofs.CheckpointRevocationProof(ctx, proofRequest)
	if err != nil || len(authorizationProof) != ed25519.SignatureSize {
		return errors.Join(ErrCheckpointIntegrity, err)
	}
	authorizationHash := sha256.Sum256(authorizationProof)
	if err := p.executeRevocationFence(ctx, endpoint, next, operationID, authorizationHash, authorizationProof); err != nil {
		return err
	}
	type response struct {
		trust   CheckpointWitnessTrust
		receipt CheckpointWitnessReceipt
		err     error
	}
	ch := make(chan response, len(p.Witnesses))
	for _, trust := range p.Witnesses {
		trust := trust
		go func() {
			receipt, err := trust.Witness.Revoke(ctx, endpoint, next)
			ch <- response{trust: trust, receipt: receipt, err: err}
		}()
	}
	valid := 0
	var canonical *CheckpointWitnessReceipt
	for range p.Witnesses {
		r := <-ch
		if r.err != nil || VerifyCheckpointWitnessReceipt(r.receipt, r.trust.ID, r.trust.PublicKey) != nil ||
			r.receipt.Kind != "revoke" || r.receipt.Scope != witnessScope(endpoint) || r.receipt.RevocationEpoch != next {
			continue
		}
		if canonical == nil {
			copy := r.receipt
			canonical = &copy
			valid = 1
		} else if sameWitnessRecord(*canonical, r.receipt) {
			valid++
		} else {
			return ErrCheckpointWitnessDisagreement
		}
	}
	if valid < p.Quorum {
		return ErrCheckpointQuorum
	}
	return nil
}

func (p *WitnessedReplayCheckpointProvider) Head(ctx context.Context, endpoint CheckpointEndpoint) (CheckpointHead, error) {
	if err := p.ValidateConfiguration(); err != nil {
		return CheckpointHead{}, err
	}
	primary, err := p.Primary.Head(ctx, endpoint)
	if err != nil {
		return CheckpointHead{}, err
	}
	if err := VerifyCheckpointHead(primary, endpoint, p.PrimaryKey); err != nil {
		return CheckpointHead{}, err
	}
	type response struct {
		trust CheckpointWitnessTrust
		head  CheckpointWitnessHead
		err   error
	}
	ch := make(chan response, len(p.Witnesses))
	for _, trust := range p.Witnesses {
		trust := trust
		go func() {
			head, err := trust.Witness.Head(ctx, witnessScope(endpoint))
			ch <- response{trust: trust, head: head, err: err}
		}()
	}
	var canonical *CheckpointWitnessHead
	valid := 0
	for range p.Witnesses {
		r := <-ch
		if r.err != nil || VerifyCheckpointWitnessHead(r.head, r.trust.ID, r.trust.PublicKey) != nil ||
			r.head.Scope != witnessScope(endpoint) {
			continue
		}
		if canonical == nil {
			copy := r.head
			canonical = &copy
			valid = 1
		} else if sameWitnessHead(*canonical, r.head) {
			valid++
		} else {
			return CheckpointHead{}, ErrCheckpointWitnessDisagreement
		}
	}
	if valid < p.Quorum || canonical == nil {
		return CheckpointHead{}, ErrCheckpointQuorum
	}
	if canonical.PrimaryGeneration != primary.Generation || canonical.PrimaryHead != primary.RecordHash ||
		canonical.RevocationEpoch != primary.RevocationEpoch {
		return CheckpointHead{}, ErrCheckpointWitnessRollback
	}
	return primary, nil
}

func (p *WitnessedReplayCheckpointProvider) verifyRequestMembershipVector(ctx context.Context, request CheckpointRequest) error {
	if _, err := CheckpointRequestFingerprint(request); err != nil {
		return err
	}
	for _, endpoint := range checkpointRequestParticipants(request) {
		head, err := p.Head(ctx, endpoint)
		if err != nil {
			return err
		}
		if head.RevocationEpoch != endpoint.RevocationEpoch {
			return ErrCheckpointRevoked
		}
	}
	return nil
}

func committedCheckpointAckCount(acks []CheckpointWitnessAck) int {
	count := 0
	for _, ack := range acks {
		if ack.Decision == "committed" {
			count++
		}
	}
	return count
}

func (p *WitnessedReplayCheckpointProvider) acknowledgeWitnessQuorum(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, store checkpointPendingAcknowledgements) (result []CheckpointWitnessAck, resultErr error) {
	if p == nil {
		return nil, ErrCheckpointUnavailable
	}
	locker, ok := p.Pending.(checkpointPendingFinalizationLocker)
	if !ok {
		return nil, ErrCheckpointUnavailable
	}
	unlock, err := locker.LockFinalization(ctx, request)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	return p.acknowledgeWitnessQuorumLocked(ctx, request, receipt, store)
}

func (p *WitnessedReplayCheckpointProvider) acknowledgeWitnessQuorumLocked(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, store checkpointPendingAcknowledgements) ([]CheckpointWitnessAck, error) {
	acks, err := store.LoadAcknowledgements(ctx, request, receipt, p.Witnesses)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]CheckpointWitnessAck, len(acks))
	for _, ack := range acks {
		seen[ack.WitnessID] = ack
	}

	type response struct {
		trust CheckpointWitnessTrust
		ack   CheckpointWitnessAck
		err   error
	}
	query := make([]CheckpointWitnessTrust, 0, len(p.Witnesses))
	if committedCheckpointAckCount(acks) >= p.Quorum {
		// Probe every witness with a persisted terminal decision, including
		// negative votes, but do not require unrelated witnesses to be online.
		for _, ack := range acks {
			for _, trust := range p.Witnesses {
				if trust.ID == ack.WitnessID {
					query = append(query, trust)
					break
				}
			}
		}
	} else {
		query = append(query, p.Witnesses...)
	}

	ch := make(chan response, len(query))
	for _, trust := range query {
		trust := trust
		go func() {
			ack, err := trust.Witness.Acknowledge(ctx, request, receipt)
			ch <- response{trust: trust, ack: ack, err: err}
		}()
	}

	newAcks := make([]response, 0, len(query))
	type conflict struct {
		trust       CheckpointWitnessTrust
		original    CheckpointWitnessAck
		conflicting CheckpointWitnessAck
	}
	conflicts := make([]conflict, 0)
	for range query {
		r := <-ch
		if r.err != nil || VerifyCheckpointWitnessAck(r.ack, r.trust.ID, r.trust.PublicKey) != nil ||
			!checkpointAckMatchesOperation(r.ack, request, receipt) {
			// Invalid signatures and wrong-operation responses never enter the journal.
			continue
		}
		if previous, ok := seen[r.trust.ID]; ok {
			if previous.Decision != r.ack.Decision {
				conflicts = append(conflicts, conflict{trust: r.trust, original: previous, conflicting: r.ack})
			}
			continue
		}
		newAcks = append(newAcks, r)
		seen[r.trust.ID] = r.ack
	}

	writer, ok := p.Pending.(checkpointPendingDecisionWriter)
	if !ok {
		return nil, ErrCheckpointUnavailable
	}
	// Persist every first-seen authenticated decision before publishing the
	// terminal conflict state. Otherwise a fast conflict response could discard
	// valid first-seen decisions returned by other witnesses in the same batch.
	for _, r := range newAcks {
		if err := writer.recordAcknowledgementLocked(ctx, request, receipt, r.ack, r.trust); err != nil {
			return nil, err
		}
	}
	for _, c := range conflicts {
		if err := writer.recordEquivocationLocked(ctx, request, receipt, c.original, c.conflicting, c.trust); err != nil {
			return nil, errors.Join(ErrCheckpointUnavailable, err)
		}
	}
	if len(conflicts) != 0 {
		return nil, ErrCheckpointConflict
	}
	acks, err = store.LoadAcknowledgements(ctx, request, receipt, p.Witnesses)
	if err != nil {
		return nil, err
	}
	if committedCheckpointAckCount(acks) < p.Quorum {
		return nil, ErrCheckpointQuorum
	}
	if err := p.verifyRequestMembershipVector(ctx, request); err != nil {
		return nil, err
	}
	return acks, nil
}

func (p *WitnessedReplayCheckpointProvider) preflightWitnessHeads(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, existingPending bool, disposition CheckpointDisposition) error {
	type response struct {
		trust CheckpointWitnessTrust
		head  CheckpointWitnessHead
		err   error
	}
	ch := make(chan response, len(p.Witnesses))
	for _, trust := range p.Witnesses {
		trust := trust
		go func() {
			head, err := trust.Witness.Head(ctx, witnessScope(checkpointEndpointForConsumer(request)))
			ch <- response{trust: trust, head: head, err: err}
		}()
	}
	valid, alreadyCommitted := 0, 0
	expectedScope := witnessScope(checkpointEndpointForConsumer(request))
	for range p.Witnesses {
		r := <-ch
		if r.err != nil || VerifyCheckpointWitnessHead(r.head, r.trust.ID, r.trust.PublicKey) != nil ||
			r.head.Scope != expectedScope {
			continue
		}
		valid++
		switch {
		case r.head.PrimaryGeneration == receipt.Generation && r.head.PrimaryHead == receipt.RecordHash && r.head.RevocationEpoch == checkpointEndpointForConsumer(request).RevocationEpoch:
			alreadyCommitted++
		case r.head.PrimaryGeneration+1 == receipt.Generation && r.head.PrimaryHead == receipt.PreviousHash && r.head.RevocationEpoch == checkpointEndpointForConsumer(request).RevocationEpoch:
		default:
			return ErrCheckpointWitnessRollback
		}
	}
	if valid < p.Quorum {
		return ErrCheckpointQuorum
	}
	if alreadyCommitted > 0 && (!existingPending || disposition != CheckpointRecovered) {
		return ErrCheckpointHistorical
	}
	return nil
}

func (p *WitnessedReplayCheckpointProvider) commitWitnessQuorum(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt, existingPending bool, disposition CheckpointDisposition) ([]CheckpointWitnessReceipt, error) {
	if err := p.preflightWitnessHeads(ctx, request, receipt, existingPending, disposition); err != nil {
		return nil, err
	}
	type response struct {
		trust   CheckpointWitnessTrust
		receipt CheckpointWitnessReceipt
		err     error
	}
	ch := make(chan response, len(p.Witnesses))
	for _, trust := range p.Witnesses {
		trust := trust
		go func() {
			witnessReceipt, err := trust.Witness.Commit(ctx, request, receipt)
			ch <- response{trust: trust, receipt: witnessReceipt, err: err}
		}()
	}
	receipts := make([]CheckpointWitnessReceipt, 0, len(p.Witnesses))
	var canonical *CheckpointWitnessReceipt
	for range p.Witnesses {
		r := <-ch
		if r.err != nil || VerifyCheckpointWitnessReceipt(r.receipt, r.trust.ID, r.trust.PublicKey) != nil ||
			r.receipt.Kind != "consume" || r.receipt.Scope != witnessScope(checkpointEndpointForConsumer(request)) ||
			r.receipt.PrimaryReceiptSHA256 != sha256.Sum256(checkpointReceiptMessage(receipt)) ||
			r.receipt.RequestSHA256 != receipt.RequestSHA256 || r.receipt.JTI != receipt.JTI ||
			r.receipt.AuthorizationSHA256 != receipt.AuthorizationSHA256 {
			continue
		}
		if canonical == nil {
			copy := r.receipt
			canonical = &copy
		} else if !sameWitnessRecord(*canonical, r.receipt) {
			return nil, ErrCheckpointWitnessDisagreement
		}
		receipts = append(receipts, r.receipt)
	}
	if len(receipts) < p.Quorum {
		return nil, ErrCheckpointQuorum
	}
	return receipts, nil
}

func sameCheckpointWitnessAckOutcome(a, b CheckpointWitnessAck) bool {
	return a.WitnessID == b.WitnessID && a.Scope == b.Scope && a.JTI == b.JTI &&
		a.RequestSHA256 == b.RequestSHA256 && a.PrimaryReceiptSHA256 == b.PrimaryReceiptSHA256 &&
		a.Decision == b.Decision && a.WitnessKeyID == b.WitnessKeyID
}

func sameCheckpointWitnessAck(a, b CheckpointWitnessAck) bool {
	return sameCheckpointWitnessAckOutcome(a, b) && bytes.Equal(a.Signature, b.Signature)
}

func checkpointAckMatchesOperation(ack CheckpointWitnessAck, request CheckpointRequest, receipt CheckpointReceipt) bool {
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return false
	}
	return ack.Scope == witnessScope(checkpointEndpointForConsumer(request)) &&
		ack.JTI == request.JTI && ack.RequestSHA256 == fingerprint &&
		ack.PrimaryReceiptSHA256 == sha256.Sum256(checkpointReceiptMessage(receipt))
}

func validWitnessConfiguration(witnesses []CheckpointWitnessTrust, quorum int, primaryKey ed25519.PublicKey) bool {
	if len(primaryKey) != ed25519.PublicKeySize || !validWitnessSet(witnesses, quorum) {
		return false
	}
	for _, witness := range witnesses {
		if bytes.Equal(witness.PublicKey, primaryKey) {
			return false
		}
	}
	return true
}

func validWitnessSet(witnesses []CheckpointWitnessTrust, quorum int) bool {
	if len(witnesses) < 2 || quorum <= len(witnesses)/2 || quorum > len(witnesses) {
		return false
	}
	seen := make(map[string]bool, len(witnesses))
	keys := make(map[[sha256.Size]byte]bool, len(witnesses))
	for _, witness := range witnesses {
		if witness.Witness == nil || witness.ID == "" || seen[witness.ID] || len(witness.PublicKey) != ed25519.PublicKeySize {
			return false
		}
		seen[witness.ID] = true
		keyHash := sha256.Sum256(witness.PublicKey)
		if keys[keyHash] {
			return false
		}
		keys[keyHash] = true
	}
	return true
}

func witnessScope(endpoint CheckpointEndpoint) CheckpointWitnessScope {
	return CheckpointWitnessScope{DeviceID: endpoint.DeviceID, AccountID: endpoint.AccountID, OrganizationID: endpoint.OrganizationID}
}

func checkpointEndpointForConsumer(request CheckpointRequest) CheckpointEndpoint {
	endpoint, _ := checkpointConsumer(request)
	return endpoint
}

// checkpointRequestParticipants returns the complete signed membership vector.
// CheckpointRequestFingerprint validates the route/router pairing before callers
// use this list, so an omitted or ambiguous router cannot silently downgrade trust.
func checkpointRequestParticipants(request CheckpointRequest) []CheckpointEndpoint {
	participants := []CheckpointEndpoint{request.Initiator, request.Destination}
	if request.RouteAuthorizationSHA256 != ([sha256.Size]byte{}) {
		participants = append(participants, request.Router)
	}
	return participants
}

func VerifyCheckpointWitnessReceipt(receipt CheckpointWitnessReceipt, witnessID string, publicKey ed25519.PublicKey) error {
	if witnessID == "" || receipt.WitnessID != witnessID || len(publicKey) != ed25519.PublicKeySize ||
		receipt.WitnessKeyID != checkpointProviderKeyID(publicKey) || receipt.Generation == 0 ||
		!validCheckpointEndpoint(CheckpointEndpoint{DeviceID: receipt.Scope.DeviceID, AccountID: receipt.Scope.AccountID, OrganizationID: receipt.Scope.OrganizationID}) ||
		(receipt.Kind != "consume" && receipt.Kind != "revoke") || len(receipt.Signature) != ed25519.SignatureSize {
		return ErrCheckpointIntegrity
	}
	if receipt.RecordHash != checkpointWitnessRecordHash(receipt) ||
		!ed25519.Verify(publicKey, checkpointWitnessReceiptMessage(receipt), receipt.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

func validCheckpointWitnessAckDecision(decision string) bool {
	return decision == "committed" || decision == "revoked" || decision == "aborted"
}

func VerifyCheckpointWitnessAck(ack CheckpointWitnessAck, witnessID string, publicKey ed25519.PublicKey) error {
	if witnessID == "" || ack.WitnessID != witnessID || len(publicKey) != ed25519.PublicKeySize ||
		ack.WitnessKeyID != checkpointProviderKeyID(publicKey) ||
		!validCheckpointWitnessAckDecision(ack.Decision) ||
		(ack.Status != "acknowledged" && ack.Status != "already_acknowledged") ||
		!validCheckpointEndpoint(CheckpointEndpoint{DeviceID: ack.Scope.DeviceID, AccountID: ack.Scope.AccountID, OrganizationID: ack.Scope.OrganizationID}) ||
		len(ack.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, checkpointWitnessAckMessage(ack), ack.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

func checkpointWitnessAckMessage(ack CheckpointWitnessAck) []byte {
	var b bytes.Buffer
	io.WriteString(&b, "wedecent-independent-witness-ack-v2\n")
	putWitnessString(&b, ack.WitnessID)
	putWitnessString(&b, ack.Scope.DeviceID)
	putWitnessString(&b, ack.Scope.AccountID)
	putWitnessString(&b, ack.Scope.OrganizationID)
	putWitnessString(&b, ack.JTI)
	b.Write(ack.RequestSHA256[:])
	b.Write(ack.PrimaryReceiptSHA256[:])
	putWitnessString(&b, ack.Decision)
	putWitnessString(&b, ack.WitnessKeyID)
	return b.Bytes()
}

func VerifyCheckpointWitnessHead(head CheckpointWitnessHead, witnessID string, publicKey ed25519.PublicKey) error {
	if witnessID == "" || head.WitnessID != witnessID || len(publicKey) != ed25519.PublicKeySize ||
		head.WitnessKeyID != checkpointProviderKeyID(publicKey) ||
		!validCheckpointEndpoint(CheckpointEndpoint{DeviceID: head.Scope.DeviceID, AccountID: head.Scope.AccountID, OrganizationID: head.Scope.OrganizationID}) ||
		len(head.Signature) != ed25519.SignatureSize {
		return ErrCheckpointIntegrity
	}
	if head.Generation == 0 && (head.RecordHash != ([sha256.Size]byte{}) || head.PrimaryGeneration != 0 || head.PrimaryHead != ([sha256.Size]byte{})) {
		return ErrCheckpointIntegrity
	}
	if !ed25519.Verify(publicKey, checkpointWitnessHeadMessage(head), head.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

func sameWitnessRecord(a, b CheckpointWitnessReceipt) bool {
	return a.Scope == b.Scope && a.Kind == b.Kind && a.Generation == b.Generation &&
		a.PreviousHash == b.PreviousHash && a.RecordHash == b.RecordHash &&
		a.PrimaryGeneration == b.PrimaryGeneration && a.PrimaryHead == b.PrimaryHead &&
		a.PrimaryReceiptSHA256 == b.PrimaryReceiptSHA256 && a.RequestSHA256 == b.RequestSHA256 &&
		a.JTI == b.JTI && a.AuthorizationSHA256 == b.AuthorizationSHA256 &&
		a.RevocationEpoch == b.RevocationEpoch && a.ProviderKeyID == b.ProviderKeyID
}

func sameWitnessHead(a, b CheckpointWitnessHead) bool {
	return a.Scope == b.Scope && a.Generation == b.Generation && a.RecordHash == b.RecordHash &&
		a.PrimaryGeneration == b.PrimaryGeneration && a.PrimaryHead == b.PrimaryHead &&
		a.RevocationEpoch == b.RevocationEpoch
}

func checkpointWitnessRecordHash(receipt CheckpointWitnessReceipt) [sha256.Size]byte {
	var b bytes.Buffer
	io.WriteString(&b, "wedecent-independent-witness-commitment-v1\n")
	putWitnessString(&b, receipt.Scope.DeviceID)
	putWitnessString(&b, receipt.Scope.AccountID)
	putWitnessString(&b, receipt.Scope.OrganizationID)
	putWitnessString(&b, receipt.Kind)
	binary.Write(&b, binary.BigEndian, receipt.Generation)
	b.Write(receipt.PreviousHash[:])
	binary.Write(&b, binary.BigEndian, receipt.PrimaryGeneration)
	b.Write(receipt.PrimaryHead[:])
	b.Write(receipt.PrimaryReceiptSHA256[:])
	b.Write(receipt.RequestSHA256[:])
	putWitnessString(&b, receipt.JTI)
	b.Write(receipt.AuthorizationSHA256[:])
	binary.Write(&b, binary.BigEndian, receipt.RevocationEpoch)
	putWitnessString(&b, receipt.ProviderKeyID)
	return sha256.Sum256(b.Bytes())
}

func checkpointWitnessReceiptMessage(receipt CheckpointWitnessReceipt) []byte {
	var b bytes.Buffer
	io.WriteString(&b, "wedecent-independent-witness-record-v1\n")
	putWitnessString(&b, receipt.WitnessID)
	putWitnessString(&b, receipt.Scope.DeviceID)
	putWitnessString(&b, receipt.Scope.AccountID)
	putWitnessString(&b, receipt.Scope.OrganizationID)
	putWitnessString(&b, receipt.Kind)
	binary.Write(&b, binary.BigEndian, receipt.Generation)
	b.Write(receipt.PreviousHash[:])
	b.Write(receipt.RecordHash[:])
	binary.Write(&b, binary.BigEndian, receipt.PrimaryGeneration)
	b.Write(receipt.PrimaryHead[:])
	b.Write(receipt.PrimaryReceiptSHA256[:])
	b.Write(receipt.RequestSHA256[:])
	putWitnessString(&b, receipt.JTI)
	b.Write(receipt.AuthorizationSHA256[:])
	binary.Write(&b, binary.BigEndian, receipt.RevocationEpoch)
	putWitnessString(&b, receipt.ProviderKeyID)
	putWitnessString(&b, receipt.WitnessKeyID)
	return b.Bytes()
}

func checkpointWitnessHeadMessage(head CheckpointWitnessHead) []byte {
	var b bytes.Buffer
	io.WriteString(&b, "wedecent-independent-witness-head-v1\n")
	putWitnessString(&b, head.WitnessID)
	putWitnessString(&b, head.Scope.DeviceID)
	putWitnessString(&b, head.Scope.AccountID)
	putWitnessString(&b, head.Scope.OrganizationID)
	binary.Write(&b, binary.BigEndian, head.Generation)
	b.Write(head.RecordHash[:])
	binary.Write(&b, binary.BigEndian, head.PrimaryGeneration)
	b.Write(head.PrimaryHead[:])
	binary.Write(&b, binary.BigEndian, head.RevocationEpoch)
	putWitnessString(&b, head.WitnessKeyID)
	return b.Bytes()
}

func putWitnessString(b *bytes.Buffer, value string) {
	binary.Write(b, binary.BigEndian, uint32(len(value)))
	io.WriteString(b, value)
}

// deterministicCheckpointWitness is a test harness, never a production provider.
type deterministicCheckpointWitness struct {
	mu           sync.Mutex
	id           string
	private      ed25519.PrivateKey
	primaryKey   ed25519.PublicKey
	ledgers      map[CheckpointWitnessScope]*deterministicWitnessLedger
	revoked      map[CheckpointWitnessScope]uint64
	available    bool
	history      map[CheckpointWitnessScope][]CheckpointWitnessReceipt
	acknowledged map[string][sha256.Size]byte
}

type deterministicWitnessLedger struct {
	generation        uint64
	head              [sha256.Size]byte
	primaryGeneration uint64
	primaryHead       [sha256.Size]byte
	revocationEpoch   uint64
	used              map[string][sha256.Size]byte
}

func newDeterministicCheckpointWitness(id string, primaryKey ed25519.PublicKey) *deterministicCheckpointWitness {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	return &deterministicCheckpointWitness{id: id, private: private, primaryKey: append(ed25519.PublicKey(nil), primaryKey...),
		ledgers: make(map[CheckpointWitnessScope]*deterministicWitnessLedger), revoked: make(map[CheckpointWitnessScope]uint64), available: true}
}

func (w *deterministicCheckpointWitness) Commit(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt) (CheckpointWitnessReceipt, error) {
	if err := ctx.Err(); err != nil {
		return CheckpointWitnessReceipt{}, err
	}
	if w == nil {
		return CheckpointWitnessReceipt{}, ErrCheckpointUnavailable
	}
	if err := VerifyCheckpointReceipt(receipt, request, w.primaryKey); err != nil {
		return CheckpointWitnessReceipt{}, err
	}
	endpoint := checkpointEndpointForConsumer(request)
	scope := witnessScope(endpoint)
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return CheckpointWitnessReceipt{}, err
	}
	primaryDigest := sha256.Sum256(checkpointReceiptMessage(receipt))
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.available {
		return CheckpointWitnessReceipt{}, ErrCheckpointUnavailable
	}
	// The witness lock is the local linearization point between Commit and
	// Revoke. Every identity carried by the signed request must still be current.
	if err := w.validateRequestMembershipVector(request); err != nil {
		return CheckpointWitnessReceipt{}, err
	}
	ledger := w.ledgers[scope]
	if ledger == nil {
		ledger = &deterministicWitnessLedger{used: make(map[string][sha256.Size]byte)}
		w.ledgers[scope] = ledger
	}
	if old, ok := ledger.used[request.JTI]; ok {
		if old != primaryDigest {
			return CheckpointWitnessReceipt{}, ErrCheckpointConflict
		}
		for _, record := range w.historyFor(scope) {
			if record.JTI == request.JTI {
				return record, nil
			}
		}
		return CheckpointWitnessReceipt{}, ErrCheckpointIntegrity
	}
	if receipt.Generation != ledger.primaryGeneration+1 || receipt.PreviousHash != ledger.primaryHead {
		return CheckpointWitnessReceipt{}, ErrCheckpointWitnessRollback
	}
	result := CheckpointWitnessReceipt{WitnessID: w.id, Scope: scope, Kind: "consume", Generation: ledger.generation + 1,
		PreviousHash: ledger.head, PrimaryGeneration: receipt.Generation, PrimaryHead: receipt.RecordHash,
		PrimaryReceiptSHA256: primaryDigest, RequestSHA256: fingerprint, JTI: request.JTI,
		AuthorizationSHA256: request.AuthorizationSHA256, RevocationEpoch: endpoint.RevocationEpoch,
		ProviderKeyID: receipt.ProviderKeyID, WitnessKeyID: checkpointProviderKeyID(w.private.Public().(ed25519.PublicKey))}
	result.RecordHash = checkpointWitnessRecordHash(result)
	result.Signature = ed25519.Sign(w.private, checkpointWitnessReceiptMessage(result))
	ledger.generation, ledger.head = result.Generation, result.RecordHash
	ledger.primaryGeneration, ledger.primaryHead = receipt.Generation, receipt.RecordHash
	ledger.used[request.JTI] = primaryDigest
	w.remember(result)
	return result, nil
}

func (w *deterministicCheckpointWitness) Revoke(ctx context.Context, endpoint CheckpointEndpoint, next uint64) (CheckpointWitnessReceipt, error) {
	if err := ctx.Err(); err != nil {
		return CheckpointWitnessReceipt{}, err
	}
	if w == nil || !validCheckpointEndpoint(endpoint) || next == 0 {
		return CheckpointWitnessReceipt{}, ErrCheckpointIntegrity
	}
	scope := witnessScope(endpoint)
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.available {
		return CheckpointWitnessReceipt{}, ErrCheckpointUnavailable
	}
	if next < w.revoked[scope] {
		return CheckpointWitnessReceipt{}, ErrCheckpointStale
	}
	if next == w.revoked[scope] {
		for i := len(w.historyFor(scope)) - 1; i >= 0; i-- {
			record := w.historyFor(scope)[i]
			if record.Kind == "revoke" && record.RevocationEpoch == next {
				return record, nil
			}
		}
		return CheckpointWitnessReceipt{}, ErrCheckpointStale
	}
	ledger := w.ledgers[scope]
	if ledger == nil {
		ledger = &deterministicWitnessLedger{used: make(map[string][sha256.Size]byte)}
		w.ledgers[scope] = ledger
	}
	result := CheckpointWitnessReceipt{WitnessID: w.id, Scope: scope, Kind: "revoke", Generation: ledger.generation + 1,
		PreviousHash: ledger.head, PrimaryGeneration: ledger.primaryGeneration, PrimaryHead: ledger.primaryHead,
		RevocationEpoch: next, WitnessKeyID: checkpointProviderKeyID(w.private.Public().(ed25519.PublicKey))}
	result.RecordHash = checkpointWitnessRecordHash(result)
	result.Signature = ed25519.Sign(w.private, checkpointWitnessReceiptMessage(result))
	ledger.generation, ledger.head, ledger.revocationEpoch = result.Generation, result.RecordHash, next
	w.revoked[scope] = next
	w.remember(result)
	return result, nil
}

func (w *deterministicCheckpointWitness) Acknowledge(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt) (CheckpointWitnessAck, error) {
	if err := ctx.Err(); err != nil {
		return CheckpointWitnessAck{}, err
	}
	if w == nil {
		return CheckpointWitnessAck{}, ErrCheckpointUnavailable
	}
	if err := VerifyCheckpointReceipt(receipt, request, w.primaryKey); err != nil {
		return CheckpointWitnessAck{}, err
	}
	scope := witnessScope(checkpointEndpointForConsumer(request))
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return CheckpointWitnessAck{}, err
	}
	digest := sha256.Sum256(checkpointReceiptMessage(receipt))
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.available {
		return CheckpointWitnessAck{}, ErrCheckpointUnavailable
	}
	// Acknowledgement is another authorization boundary: revocation of
	// either endpoint or the signed router fences completion of this request.
	if err := w.validateRequestMembershipVector(request); err != nil {
		return CheckpointWitnessAck{}, err
	}
	ledger := w.ledgers[scope]
	if ledger == nil || ledger.used[request.JTI] != digest {
		return CheckpointWitnessAck{}, ErrCheckpointHistorical
	}
	if w.acknowledged == nil {
		w.acknowledged = make(map[string][sha256.Size]byte)
	}
	key := scope.DeviceID + "|" + scope.AccountID + "|" + scope.OrganizationID + "|" + request.JTI
	status := "acknowledged"
	if old, ok := w.acknowledged[key]; ok {
		if old != digest {
			return CheckpointWitnessAck{}, ErrCheckpointConflict
		}
		status = "already_acknowledged"
	} else {
		w.acknowledged[key] = digest
	}
	ack := CheckpointWitnessAck{WitnessID: w.id, Scope: scope, JTI: request.JTI, RequestSHA256: fingerprint,
		PrimaryReceiptSHA256: digest, Decision: "committed", Status: status, WitnessKeyID: checkpointProviderKeyID(w.private.Public().(ed25519.PublicKey))}
	ack.Signature = ed25519.Sign(w.private, checkpointWitnessAckMessage(ack))
	return ack, nil
}

func (w *deterministicCheckpointWitness) validateRequestMembershipVector(request CheckpointRequest) error {
	for _, endpoint := range checkpointRequestParticipants(request) {
		scope := witnessScope(endpoint)
		currentEpoch := w.revoked[scope]
		if endpoint.RevocationEpoch != currentEpoch {
			return ErrCheckpointRevoked
		}
		if ledger := w.ledgers[scope]; ledger != nil && ledger.revocationEpoch != currentEpoch {
			return ErrCheckpointIntegrity
		}
	}
	return nil
}

func (w *deterministicCheckpointWitness) Head(ctx context.Context, scope CheckpointWitnessScope) (CheckpointWitnessHead, error) {
	if err := ctx.Err(); err != nil {
		return CheckpointWitnessHead{}, err
	}
	if w == nil {
		return CheckpointWitnessHead{}, ErrCheckpointUnavailable
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.available {
		return CheckpointWitnessHead{}, ErrCheckpointUnavailable
	}
	ledger := w.ledgers[scope]
	currentEpoch := w.revoked[scope]
	if ledger == nil {
		ledger = &deterministicWitnessLedger{used: make(map[string][sha256.Size]byte), revocationEpoch: currentEpoch}
		w.ledgers[scope] = ledger
	} else if ledger.revocationEpoch != currentEpoch {
		return CheckpointWitnessHead{}, ErrCheckpointIntegrity
	}
	head := CheckpointWitnessHead{WitnessID: w.id, Scope: scope, Generation: ledger.generation, RecordHash: ledger.head,
		PrimaryGeneration: ledger.primaryGeneration, PrimaryHead: ledger.primaryHead, RevocationEpoch: currentEpoch,
		WitnessKeyID: checkpointProviderKeyID(w.private.Public().(ed25519.PublicKey))}
	head.Signature = ed25519.Sign(w.private, checkpointWitnessHeadMessage(head))
	return head, nil
}

func (w *deterministicCheckpointWitness) historyFor(scope CheckpointWitnessScope) []CheckpointWitnessReceipt {
	return w.history[scope]
}

func (w *deterministicCheckpointWitness) remember(receipt CheckpointWitnessReceipt) {
	if w.history == nil {
		w.history = make(map[CheckpointWitnessScope][]CheckpointWitnessReceipt)
	}
	w.history[receipt.Scope] = append(w.history[receipt.Scope], receipt)
}

func organizationCheckpointFenceScope(organizationID string) CheckpointWitnessScope {
	return CheckpointWitnessScope{Kind: "organization", OrganizationID: organizationID}
}

func checkpointFenceOperationID(action CheckpointFenceAction, operationID, deviceID string) string {
	digest := sha256.Sum256([]byte("wedecent-checkpoint-fence-operation-v1\n" + string(action) + "\n" + operationID + "\n" + deviceID))
	return hex.EncodeToString(digest[:])
}

func checkpointRevocationFingerprint(endpoint CheckpointEndpoint, next uint64) [sha256.Size]byte {
	var b bytes.Buffer
	io.WriteString(&b, "wedecent-checkpoint-revocation-request-v1\n")
	for _, value := range []string{endpoint.DeviceID, endpoint.AccountID, endpoint.OrganizationID} {
		binary.Write(&b, binary.BigEndian, uint32(len(value)))
		io.WriteString(&b, value)
	}
	binary.Write(&b, binary.BigEndian, endpoint.RevocationEpoch)
	binary.Write(&b, binary.BigEndian, next)
	return sha256.Sum256(b.Bytes())
}

func checkpointFenceParticipantHeadDigest(heads []CheckpointFenceParticipantHead) ([sha256.Size]byte, error) {
	ordered := cloneCheckpointFenceParticipantHeads(heads)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Endpoint.DeviceID < ordered[j].Endpoint.DeviceID })
	var b bytes.Buffer
	io.WriteString(&b, "wedecent-checkpoint-fence-participant-heads-v1\n")
	for i, item := range ordered {
		if i > 0 && ordered[i-1].Endpoint.DeviceID == item.Endpoint.DeviceID {
			return [sha256.Size]byte{}, ErrCheckpointIntegrity
		}
		for _, value := range []string{item.Endpoint.DeviceID, item.Endpoint.AccountID, item.Endpoint.OrganizationID} {
			if len(value) > int(^uint32(0)) {
				return [sha256.Size]byte{}, ErrCheckpointIntegrity
			}
			binary.Write(&b, binary.BigEndian, uint32(len(value)))
			io.WriteString(&b, value)
		}
		b.Write(checkpointHeadMessage(item.Head))
		binary.Write(&b, binary.BigEndian, uint32(len(item.Head.Signature)))
		b.Write(item.Head.Signature)
	}
	return sha256.Sum256(b.Bytes()), nil
}

func (p *WitnessedReplayCheckpointProvider) checkpointParticipantHeads(ctx context.Context, participants []CheckpointEndpoint) ([]CheckpointFenceParticipantHead, error) {
	return p.checkpointParticipantHeadsWithRecovery(ctx, participants, false)
}

func (p *WitnessedReplayCheckpointProvider) checkpointParticipantHeadsWithRecovery(ctx context.Context, participants []CheckpointEndpoint, allowAdvancedEpoch bool) ([]CheckpointFenceParticipantHead, error) {
	heads := make([]CheckpointFenceParticipantHead, 0, len(participants))
	for _, endpoint := range participants {
		head, err := p.Primary.Head(ctx, endpoint)
		if err != nil {
			return nil, errors.Join(ErrCheckpointUnavailable, err)
		}
		if err := VerifyCheckpointHead(head, endpoint, p.PrimaryKey); err != nil {
			return nil, err
		}
		if head.RevocationEpoch < endpoint.RevocationEpoch ||
			(!allowAdvancedEpoch && head.RevocationEpoch != endpoint.RevocationEpoch) {
			return nil, ErrCheckpointRevoked
		}
		heads = append(heads, CheckpointFenceParticipantHead{Endpoint: endpoint, Head: head})
	}
	return heads, nil
}

func (p *WitnessedReplayCheckpointProvider) executeFinalizationFence(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt) (CheckpointFenceOperation, error) {
	if p == nil || p.Fencing == nil {
		return CheckpointFenceOperation{}, ErrCheckpointUnavailable
	}
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil || receipt.RequestSHA256 != fingerprint || VerifyCheckpointReceipt(receipt, request, p.PrimaryKey) != nil {
		return CheckpointFenceOperation{}, ErrCheckpointIntegrity
	}
	operationID, err := checkpointFinalizationID(request, receipt)
	if err != nil {
		return CheckpointFenceOperation{}, err
	}
	operationID = checkpointFenceOperationID(CheckpointFenceFinalize, operationID, request.Initiator.OrganizationID)
	scope := organizationCheckpointFenceScope(request.Initiator.OrganizationID)
	existing, found, err := p.Fencing.Primary.LoadFence(ctx, scope, operationID)
	if err != nil {
		return CheckpointFenceOperation{}, err
	}
	if found && existing.Committed {
		expected := CheckpointFenceRequest{
			Scope: scope, Participants: cloneCheckpointEndpoints(checkpointRequestParticipants(request)),
			Action: CheckpointFenceFinalize, OperationID: operationID,
			RequestSHA256: fingerprint, AuthorizationSHA256: request.AuthorizationSHA256,
			WitnessSetVersion: p.Fencing.WitnessSetVersion,
			WitnessIDs:        checkpointFenceClientIDs(p.Fencing.Witnesses),
		}
		if !checkpointFenceTokenMatchesOperation(existing.Token, expected) ||
			verifyCheckpointFenceTokenSignature(existing.Token, p.Fencing.PrimaryKey) != nil {
			return CheckpointFenceOperation{}, ErrCheckpointIntegrity
		}
		if err := p.Fencing.verifyCommittedOperation(existing, existing.Token); err != nil {
			return CheckpointFenceOperation{}, err
		}
		return existing, nil
	}
	heads, err := p.checkpointParticipantHeadsWithRecovery(ctx, checkpointRequestParticipants(request), false)
	if err != nil {
		return CheckpointFenceOperation{}, err
	}
	return p.executeOrganizationFence(ctx, scope, CheckpointFenceFinalize, operationID, fingerprint, request.AuthorizationSHA256, nil, checkpointRequestParticipants(request), heads)
}

func (p *WitnessedReplayCheckpointProvider) executeRevocationFence(ctx context.Context, endpoint CheckpointEndpoint, next uint64, operationID string, authorizationHash [sha256.Size]byte, authorizationProof []byte) error {
	if p == nil || p.Fencing == nil || !validCheckpointEndpoint(endpoint) ||
		endpoint.RevocationEpoch == ^uint64(0) || next != endpoint.RevocationEpoch+1 {
		return ErrCheckpointStale
	}
	expectedOperationID, operationErr := CheckpointRevocationOperationID(endpoint, next)
	if operationErr != nil || operationID != expectedOperationID ||
		authorizationHash == ([sha256.Size]byte{}) || len(authorizationProof) != ed25519.SignatureSize {
		return ErrCheckpointIntegrity
	}
	fingerprint := checkpointRevocationFingerprint(endpoint, next)
	scope := organizationCheckpointFenceScope(endpoint.OrganizationID)
	existing, found, err := p.Fencing.Primary.LoadFence(ctx, scope, operationID)
	if err != nil {
		return err
	}
	heads, err := p.checkpointParticipantHeadsWithRecovery(ctx, []CheckpointEndpoint{endpoint}, found && existing.Committed)
	if err != nil {
		return err
	}
	_, err = p.executeOrganizationFence(ctx, scope,
		CheckpointFenceRevoke, operationID, fingerprint, authorizationHash, authorizationProof, []CheckpointEndpoint{endpoint}, heads)
	return err
}

func (p *WitnessedReplayCheckpointProvider) executeOrganizationFence(
	ctx context.Context,
	scope CheckpointWitnessScope,
	action CheckpointFenceAction,
	operationID string,
	requestHash, authorizationHash [sha256.Size]byte,
	authorizationProof []byte,
	participants []CheckpointEndpoint,
	heads []CheckpointFenceParticipantHead,
) (CheckpointFenceOperation, error) {
	if p == nil || p.Fencing == nil || ctx == nil || len(heads) == 0 {
		return CheckpointFenceOperation{}, ErrCheckpointUnavailable
	}
	reader, ok := p.Fencing.Primary.(CheckpointFenceHeadReader)
	if !ok {
		return CheckpointFenceOperation{}, ErrCheckpointUnavailable
	}
	fenceHead, err := reader.FenceHead(ctx, scope)
	if err != nil {
		return CheckpointFenceOperation{}, err
	}
	request := CheckpointFenceRequest{
		Scope: scope, Participants: cloneCheckpointEndpoints(participants),
		AuthorizationProof:      append([]byte(nil), authorizationProof...),
		ExpectedFenceGeneration: fenceHead.Generation,
		ExpectedRevocationEpoch: fenceHead.RevocationEpoch,
		Action:                  action, OperationID: operationID,
		RequestSHA256: requestHash, AuthorizationSHA256: authorizationHash,
		WitnessSetVersion: p.Fencing.WitnessSetVersion,
		WitnessIDs:        checkpointFenceClientIDs(p.Fencing.Witnesses),
	}
	existing, found, err := p.Fencing.Primary.LoadFence(ctx, scope, operationID)
	if err != nil {
		return CheckpointFenceOperation{}, err
	}
	if found {
		if !checkpointFenceTokenMatchesOperation(existing.Token, request) {
			return CheckpointFenceOperation{}, ErrCheckpointConflict
		}
		request.ExpectedFenceGeneration = existing.Token.ExpectedFenceGeneration
		request.ExpectedRevocationEpoch = existing.Token.ExpectedRevocationEpoch
		request.PrimaryHeadGeneration = existing.Token.PrimaryHeadGeneration
		request.PrimaryHeadSHA256 = existing.Token.PrimaryHeadSHA256
		request.PreviousFenceSHA256 = existing.Token.PreviousFenceSHA256
		request.ExpiresAtUnixMS = existing.Token.ExpiresAtUnixMS
	} else {
		if fenceHead.PendingOperationID != "" && fenceHead.PendingOperationID != operationID {
			return CheckpointFenceOperation{}, ErrCheckpointAmbiguous
		}
		if fenceHead.Generation == ^uint64(0) {
			return CheckpointFenceOperation{}, ErrCheckpointStale
		}
		primaryHeadDigest, err := checkpointFenceParticipantHeadDigest(heads)
		if err != nil {
			return CheckpointFenceOperation{}, err
		}
		request.PrimaryHeadGeneration = fenceHead.Generation + 1
		request.PrimaryHeadSHA256 = primaryHeadDigest
		request.PreviousFenceSHA256 = fenceHead.FenceDigest
		request.ExpiresAtUnixMS = time.Now().Add(30 * time.Second).UnixMilli()
	}
	return p.Fencing.ExecuteWithCheckpointHeads(ctx, request, heads)
}

package portforward

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"time"
)

const checkpointFenceLogMaxRecord = 1 << 20

var ErrCheckpointFenceStore = errors.New("portforward: durable fencing store unavailable")

type CheckpointFenceWitnessTrust struct {
	ID        string
	PublicKey ed25519.PublicKey
}

type CheckpointFenceOperation struct {
	Token           CheckpointFenceToken
	Acknowledgements []CheckpointFenceAcknowledgement
	Committed       bool
}

type checkpointFenceDiskEvent struct {
	Kind            string
	Token           CheckpointFenceToken
	Acknowledgements []CheckpointFenceAcknowledgement
}

type checkpointFencePrimaryScopeState struct {
	Generation              uint64
	RevocationEpoch         uint64
	FenceHead               [sha256.Size]byte
	PrimaryHeadGeneration   uint64
	PrimaryHeadSHA256       [sha256.Size]byte
	PendingOperationID      string
	Operations              map[string]CheckpointFenceOperation
}

type checkpointFencePrimaryIndex struct {
	Scopes map[CheckpointWitnessScope]*checkpointFencePrimaryScopeState
	IDs    map[string]CheckpointWitnessScope
}

type checkpointFenceWitnessScopeState struct {
	Generation            uint64
	RevocationEpoch       uint64
	FenceHead             [sha256.Size]byte
	PrimaryHeadGeneration uint64
	PrimaryHeadSHA256     [sha256.Size]byte
	Operations            map[uint64]checkpointFenceWitnessOperation
}

type checkpointFenceWitnessOperation struct {
	TokenDigest [sha256.Size]byte
	Ack         CheckpointFenceAcknowledgement
}

type checkpointFenceWitnessOperationRef struct {
	Scope       CheckpointWitnessScope
	Generation  uint64
	TokenDigest [sha256.Size]byte
}

type checkpointFenceWitnessIndex struct {
	Scopes       map[CheckpointWitnessScope]*checkpointFenceWitnessScopeState
	OperationIDs map[string]checkpointFenceWitnessOperationRef
}

type FileCheckpointFencePrimary struct {
	path              string
	privateKey        ed25519.PrivateKey
	publicKey         ed25519.PublicKey
	witnessSetVersion string
	witnesses         map[string]ed25519.PublicKey
	witnessIDs        []string
	quorum            int
	now               func() time.Time
}

type FileCheckpointFenceWitness struct {
	path              string
	id                string
	privateKey        ed25519.PrivateKey
	publicKey         ed25519.PublicKey
	primaryKey        ed25519.PublicKey
	witnessSetVersion string
	witnessIDs        []string
	now               func() time.Time
}

var (
	_ CheckpointFencingPrimary  = (*FileCheckpointFencePrimary)(nil)
	_ CheckpointFencingWitness = (*FileCheckpointFenceWitness)(nil)
)

// OpenFileCheckpointFencePrimary opens a durable primary journal. The journal
// contains signed reservations and quorum-verified commit records. Keep this
// path and its private key under the primary operator's exclusive control.
func OpenFileCheckpointFencePrimary(path string, privateKey ed25519.PrivateKey, witnessSetVersion string, witnesses []CheckpointFenceWitnessTrust) (*FileCheckpointFencePrimary, error) {
	if len(privateKey) != ed25519.PrivateKeySize || path == "" || witnessSetVersion == "" || len(witnessSetVersion) > 128 {
		return nil, ErrCheckpointIntegrity
	}
	quorum, err := CheckpointFenceQuorum(len(witnesses))
	if err != nil {
		return nil, err
	}
	trusted := make(map[string]ed25519.PublicKey, len(witnesses))
	ids := make([]string, 0, len(witnesses))
	keyHashes := make(map[[sha256.Size]byte]bool, len(witnesses))
	for _, witness := range witnesses {
		if witness.ID == "" || len(witness.ID) > 128 || len(witness.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrCheckpointIntegrity
		}
		if _, exists := trusted[witness.ID]; exists {
			return nil, ErrCheckpointIntegrity
		}
		if bytes.Equal(witness.PublicKey, privateKey.Public().(ed25519.PublicKey)) {
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
	store := &FileCheckpointFencePrimary{
		path: path, privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		publicKey: append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...),
		witnessSetVersion: witnessSetVersion, witnesses: trusted, witnessIDs: ids,
		quorum: quorum, now: time.Now,
	}
	if err := store.withIndex(context.Background(), func(_ *os.File, _ *checkpointFencePrimaryIndex) error { return nil }); err != nil {
		return nil, err
	}
	return store, nil
}

// OpenFileCheckpointFenceWitness opens one independently administered witness
// journal with its own signing key and durable state.
func OpenFileCheckpointFenceWitness(path, witnessID string, privateKey ed25519.PrivateKey, primaryKey ed25519.PublicKey, witnessSetVersion string, witnessIDs []string) (*FileCheckpointFenceWitness, error) {
	if path == "" || witnessID == "" || len(witnessID) > 128 ||
		len(privateKey) != ed25519.PrivateKeySize || len(primaryKey) != ed25519.PublicKeySize ||
		witnessSetVersion == "" || len(witnessSetVersion) > 128 {
		return nil, ErrCheckpointIntegrity
	}
	if _, err := CheckpointFenceQuorum(len(witnessIDs)); err != nil {
		return nil, err
	}
	ids := append([]string(nil), witnessIDs...)
	sort.Strings(ids)
	found := false
	for i, id := range ids {
		if id == "" || len(id) > 128 || (i > 0 && ids[i-1] == id) {
			return nil, ErrCheckpointIntegrity
		}
		if id == witnessID {
			found = true
		}
	}
	if !found || bytes.Equal(privateKey.Public().(ed25519.PublicKey), primaryKey) {
		return nil, ErrCheckpointIntegrity
	}
	store := &FileCheckpointFenceWitness{
		path: path, id: witnessID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		publicKey: append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...),
		primaryKey: append(ed25519.PublicKey(nil), primaryKey...),
		witnessSetVersion: witnessSetVersion, witnessIDs: ids, now: time.Now,
	}
	if err := store.withIndex(context.Background(), func(_ *os.File, _ *checkpointFenceWitnessIndex) error { return nil }); err != nil {
		return nil, err
	}
	return store, nil
}

func (p *FileCheckpointFencePrimary) ReserveFence(ctx context.Context, request CheckpointFenceRequest) (CheckpointFenceToken, error) {
	if p == nil || ctx == nil || !validCheckpointFenceScope(request.Scope) {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	var result CheckpointFenceToken
	err := p.withIndex(ctx, func(file *os.File, index *checkpointFencePrimaryIndex) error {
		scope := index.Scopes[request.Scope]
		if scope == nil {
			scope = newCheckpointFencePrimaryScope()
			index.Scopes[request.Scope] = scope
		}
		if existingScope, exists := index.IDs[request.OperationID]; exists && existingScope != request.Scope {
			return ErrCheckpointConflict
		}
		if existing, exists := scope.Operations[request.OperationID]; exists {
			candidate, err := p.tokenForRequest(request)
			if err != nil {
				return err
			}
			want, err := CheckpointFenceTokenDigest(candidate)
			if err != nil {
				return err
			}
			got, err := CheckpointFenceTokenDigest(existing.Token)
			if err != nil || want != got {
				return ErrCheckpointConflict
			}
			result = cloneCheckpointFenceToken(existing.Token)
			return nil
		}
		if request.OperationID == "" || scope.PendingOperationID != "" ||
			request.ExpectedFenceGeneration != scope.Generation ||
			request.ExpectedRevocationEpoch != scope.RevocationEpoch ||
			request.PreviousFenceSHA256 != scope.FenceHead ||
			!validFencePrimaryHeadLink(scope, request.PrimaryHeadGeneration, request.PrimaryHeadSHA256) {
			return ErrCheckpointStale
		}
		token, err := p.tokenForRequest(request)
		if err != nil {
			return err
		}
		if token.ExpiresAtUnixMS <= p.now().UnixMilli() {
			return ErrCheckpointStale
		}
		if err := appendCheckpointFenceEvent(file, checkpointFenceDiskEvent{Kind: "reserve", Token: token}); err != nil {
			return err
		}
		if err := applyCheckpointFencePrimaryEvent(index, checkpointFenceDiskEvent{Kind: "reserve", Token: token}, p); err != nil {
			return errors.Join(ErrCheckpointIntegrity, err)
		}
		result = cloneCheckpointFenceToken(token)
		return nil
	})
	if err != nil {
		return CheckpointFenceToken{}, err
	}
	return result, nil
}

func (p *FileCheckpointFencePrimary) CommitFence(ctx context.Context, token CheckpointFenceToken, acknowledgements []CheckpointFenceAcknowledgement) error {
	if p == nil || ctx == nil {
		return ErrCheckpointUnavailable
	}
	return p.withIndex(ctx, func(file *os.File, index *checkpointFencePrimaryIndex) error {
		scope := index.Scopes[token.Scope]
		if scope == nil {
			return ErrCheckpointHistorical
		}
		existing, ok := scope.Operations[token.OperationID]
		if !ok {
			return ErrCheckpointHistorical
		}
		want, err := CheckpointFenceTokenDigest(existing.Token)
		if err != nil {
			return err
		}
		got, err := CheckpointFenceTokenDigest(token)
		if err != nil || want != got || !bytes.Equal(existing.Token.Signature, token.Signature) {
			return ErrCheckpointConflict
		}
		if existing.Committed {
			return nil
		}
		if scope.PendingOperationID != token.OperationID {
			return ErrCheckpointStale
		}
		if err := p.verifyFenceAcknowledgements(token, acknowledgements); err != nil {
			return err
		}
		event := checkpointFenceDiskEvent{Kind: "commit", Token: token, Acknowledgements: cloneCheckpointFenceAcks(acknowledgements)}
		if err := appendCheckpointFenceEvent(file, event); err != nil {
			return err
		}
		return applyCheckpointFencePrimaryEvent(index, event, p)
	})
}

func (p *FileCheckpointFencePrimary) LoadFence(ctx context.Context, scope CheckpointWitnessScope, operationID string) (CheckpointFenceOperation, bool, error) {
	if p == nil || ctx == nil {
		return CheckpointFenceOperation{}, false, ErrCheckpointUnavailable
	}
	var result CheckpointFenceOperation
	var found bool
	err := p.withIndex(ctx, func(_ *os.File, index *checkpointFencePrimaryIndex) error {
		state := index.Scopes[scope]
		if state == nil {
			return nil
		}
		result, found = state.Operations[operationID]
		result.Token = cloneCheckpointFenceToken(result.Token)
		result.Acknowledgements = cloneCheckpointFenceAcks(result.Acknowledgements)
		return nil
	})
	return result, found, err
}

func (w *FileCheckpointFenceWitness) CommitFence(ctx context.Context, token CheckpointFenceToken) (CheckpointFenceAcknowledgement, error) {
	if w == nil || ctx == nil {
		return CheckpointFenceAcknowledgement{}, ErrCheckpointUnavailable
	}
	var result CheckpointFenceAcknowledgement
	err := w.withIndex(ctx, func(file *os.File, index *checkpointFenceWitnessIndex) error {
		if err := verifyCheckpointFenceTokenSignature(token, w.primaryKey); err != nil {
			return err
		}
		if token.WitnessSetVersion != w.witnessSetVersion || !sameStringSet(token.WitnessIDs, w.witnessIDs) {
			return ErrCheckpointIntegrity
		}
		state := index.Scopes[token.Scope]
		if state == nil {
			state = newCheckpointFenceWitnessScope()
			index.Scopes[token.Scope] = state
		}
		digest, err := CheckpointFenceTokenDigest(token)
		if err != nil {
			return err
		}
		if old, ok := state.Operations[token.Generation]; ok {
			if old.TokenDigest != digest || old.Ack.OperationID != token.OperationID {
				return ErrCheckpointConflict
			}
			result = cloneCheckpointFenceAck(old.Ack)
			return nil
		}
		if old, ok := index.OperationIDs[token.OperationID]; ok &&
			(old.Scope != token.Scope || old.Generation != token.Generation || old.TokenDigest != digest) {
			return ErrCheckpointConflict
		}
		committedAt := w.now().UnixMilli()
		if token.ExpiresAtUnixMS <= committedAt {
			return ErrCheckpointStale
		}
		if token.ExpectedFenceGeneration != state.Generation ||
			token.Generation != state.Generation+1 ||
			token.ExpectedRevocationEpoch != state.RevocationEpoch ||
			token.PreviousFenceSHA256 != state.FenceHead ||
			!validFencePrimaryHeadLink(state, token.PrimaryHeadGeneration, token.PrimaryHeadSHA256) {
			return ErrCheckpointStale
		}
		ack := CheckpointFenceAcknowledgement{
			WitnessID: w.id, TokenSHA256: digest, Generation: token.Generation,
			Action: token.Action, OperationID: token.OperationID,
			WitnessKeyID: checkpointProviderKeyID(w.publicKey),
			CommittedAtUnixMS: committedAt,
		}
		ack.Signature = ed25519.Sign(w.privateKey, checkpointFenceAcknowledgementMessage(ack))
		event := checkpointFenceDiskEvent{Kind: "commit", Token: token, Acknowledgements: []CheckpointFenceAcknowledgement{ack}}
		if err := appendCheckpointFenceEvent(file, event); err != nil {
			return err
		}
		if err := applyCheckpointFenceWitnessEvent(index, event, w); err != nil {
			return errors.Join(ErrCheckpointIntegrity, err)
		}
		result = cloneCheckpointFenceAck(ack)
		return nil
	})
	if err != nil {
		return CheckpointFenceAcknowledgement{}, err
	}
	return result, nil
}

func (w *FileCheckpointFenceWitness) LoadFence(ctx context.Context, scope CheckpointWitnessScope, generation uint64) (CheckpointFenceAcknowledgement, bool, error) {
	if w == nil || ctx == nil {
		return CheckpointFenceAcknowledgement{}, false, ErrCheckpointUnavailable
	}
	var result CheckpointFenceAcknowledgement
	var found bool
	err := w.withIndex(ctx, func(_ *os.File, index *checkpointFenceWitnessIndex) error {
		state := index.Scopes[scope]
		if state == nil {
			return nil
		}
		op, ok := state.Operations[generation]
		if !ok {
			return nil
		}
		result, found = cloneCheckpointFenceAck(op.Ack), true
		return nil
	})
	return result, found, err
}

func (p *FileCheckpointFencePrimary) tokenForRequest(request CheckpointFenceRequest) (CheckpointFenceToken, error) {
	if request.WitnessSetVersion != p.witnessSetVersion || !sameStringSet(request.WitnessIDs, p.witnessIDs) {
		return CheckpointFenceToken{}, ErrCheckpointIntegrity
	}
	token := CheckpointFenceToken{
		Version: checkpointFenceVersion, Scope: request.Scope,
		ExpectedFenceGeneration: request.ExpectedFenceGeneration, Generation: request.ExpectedFenceGeneration + 1,
		ExpectedRevocationEpoch: request.ExpectedRevocationEpoch, ResultingRevocationEpoch: request.ExpectedRevocationEpoch,
		Action: request.Action, OperationID: request.OperationID,
		RequestSHA256: request.RequestSHA256, AuthorizationSHA256: request.AuthorizationSHA256,
		PrimaryHeadGeneration: request.PrimaryHeadGeneration, PrimaryHeadSHA256: request.PrimaryHeadSHA256,
		PreviousFenceSHA256: request.PreviousFenceSHA256,
		WitnessSetVersion: p.witnessSetVersion, WitnessIDs: append([]string(nil), p.witnessIDs...),
		ExpiresAtUnixMS: request.ExpiresAtUnixMS,
	}
	if token.Action == CheckpointFenceRevoke {
		if token.ResultingRevocationEpoch == ^uint64(0) {
			return CheckpointFenceToken{}, ErrCheckpointStale
		}
		token.ResultingRevocationEpoch++
	}
	return SignCheckpointFenceToken(token, p.privateKey)
}

func (p *FileCheckpointFencePrimary) verifyFenceAcknowledgements(token CheckpointFenceToken, acknowledgements []CheckpointFenceAcknowledgement) error {
	digest, err := CheckpointFenceTokenDigest(token)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(acknowledgements))
	valid := 0
	for _, ack := range acknowledgements {
		key, trusted := p.witnesses[ack.WitnessID]
		if !trusted || !containsString(token.WitnessIDs, ack.WitnessID) {
			return ErrCheckpointIntegrity
		}
		if VerifyCheckpointFenceAcknowledgement(ack, ack.WitnessID, key) != nil {
			continue
		}
		if seen[ack.WitnessID] || ack.TokenSHA256 != digest ||
			ack.Generation != token.Generation || ack.Action != token.Action ||
			ack.OperationID != token.OperationID || ack.CommittedAtUnixMS > token.ExpiresAtUnixMS {
			return ErrCheckpointWitnessDisagreement
		}
		seen[ack.WitnessID] = true
		valid++
	}
	if valid < p.quorum {
		return ErrCheckpointQuorum
	}
	return nil
}

func (p *FileCheckpointFencePrimary) withIndex(ctx context.Context, fn func(*os.File, *checkpointFencePrimaryIndex) error) error {
	return withCheckpointFenceLog(ctx, p.path, func(file *os.File) error {
		index := newCheckpointFencePrimaryIndex()
		if err := replayCheckpointFenceLog(file, func(event checkpointFenceDiskEvent) error {
			return applyCheckpointFencePrimaryEvent(index, event, p)
		}); err != nil {
			return err
		}
		return fn(file, index)
	})
}

func (w *FileCheckpointFenceWitness) withIndex(ctx context.Context, fn func(*os.File, *checkpointFenceWitnessIndex) error) error {
	return withCheckpointFenceLog(ctx, w.path, func(file *os.File) error {
		index := newCheckpointFenceWitnessIndex()
		if err := replayCheckpointFenceLog(file, func(event checkpointFenceDiskEvent) error {
			return applyCheckpointFenceWitnessEvent(index, event, w)
		}); err != nil {
			return err
		}
		return fn(file, index)
	})
}

func applyCheckpointFencePrimaryEvent(index *checkpointFencePrimaryIndex, event checkpointFenceDiskEvent, p *FileCheckpointFencePrimary) error {
	if index == nil || p == nil || !validCheckpointFenceScope(event.Token.Scope) {
		return ErrCheckpointIntegrity
	}
	state := index.Scopes[event.Token.Scope]
	if state == nil {
		state = newCheckpointFencePrimaryScope()
		index.Scopes[event.Token.Scope] = state
	}
	token := event.Token
	if err := verifyCheckpointFenceTokenSignature(token, p.publicKey); err != nil ||
		token.WitnessSetVersion != p.witnessSetVersion || !sameStringSet(token.WitnessIDs, p.witnessIDs) {
		return ErrCheckpointIntegrity
	}
	digest, err := CheckpointFenceTokenDigest(token)
	if err != nil {
		return err
	}
	switch event.Kind {
	case "reserve":
		if oldScope, exists := index.IDs[token.OperationID]; exists && oldScope != token.Scope {
			return ErrCheckpointConflict
		}
		if old, exists := state.Operations[token.OperationID]; exists {
			oldDigest, _ := CheckpointFenceTokenDigest(old.Token)
			if oldDigest != digest {
				return ErrCheckpointConflict
			}
			return nil
		}
		if token.OperationID == "" || state.PendingOperationID != "" ||
			token.ExpectedFenceGeneration != state.Generation || token.Generation != state.Generation+1 ||
			token.ExpectedRevocationEpoch != state.RevocationEpoch || token.PreviousFenceSHA256 != state.FenceHead ||
			!validFencePrimaryHeadLink(state, token.PrimaryHeadGeneration, token.PrimaryHeadSHA256) {
			return ErrCheckpointStale
		}
		state.Operations[token.OperationID] = CheckpointFenceOperation{Token: cloneCheckpointFenceToken(token)}
		state.PendingOperationID = token.OperationID
		index.IDs[token.OperationID] = token.Scope
		return nil
	case "commit":
		old, exists := state.Operations[token.OperationID]
		if !exists {
			return ErrCheckpointHistorical
		}
		oldDigest, _ := CheckpointFenceTokenDigest(old.Token)
		if oldDigest != digest || !bytes.Equal(old.Token.Signature, token.Signature) {
			return ErrCheckpointConflict
		}
		if old.Committed {
			return nil
		}
		if state.PendingOperationID != token.OperationID ||
			p.verifyFenceAcknowledgements(token, event.Acknowledgements) != nil {
			return ErrCheckpointQuorum
		}
		old.Committed = true
		old.Acknowledgements = cloneCheckpointFenceAcks(event.Acknowledgements)
		state.Operations[token.OperationID] = old
		state.PendingOperationID = ""
		state.Generation = token.Generation
		state.RevocationEpoch = token.ResultingRevocationEpoch
		state.FenceHead = digest
		state.PrimaryHeadGeneration = token.PrimaryHeadGeneration
		state.PrimaryHeadSHA256 = token.PrimaryHeadSHA256
		return nil
	default:
		return ErrCheckpointIntegrity
	}
}

func applyCheckpointFenceWitnessEvent(index *checkpointFenceWitnessIndex, event checkpointFenceDiskEvent, w *FileCheckpointFenceWitness) error {
	if index == nil || w == nil || event.Kind != "commit" || !validCheckpointFenceScope(event.Token.Scope) {
		return ErrCheckpointIntegrity
	}
	token := event.Token
	if err := verifyCheckpointFenceTokenSignature(token, w.primaryKey); err != nil ||
		token.WitnessSetVersion != w.witnessSetVersion || !sameStringSet(token.WitnessIDs, w.witnessIDs) {
		return ErrCheckpointIntegrity
	}
	digest, err := CheckpointFenceTokenDigest(token)
	if err != nil {
		return err
	}
	state := index.Scopes[token.Scope]
	if state == nil {
		state = newCheckpointFenceWitnessScope()
		index.Scopes[token.Scope] = state
	}
	if len(event.Acknowledgements) != 1 {
		return ErrCheckpointIntegrity
	}
	ack := event.Acknowledgements[0]
	if ack.WitnessID != w.id || ack.TokenSHA256 != digest || ack.Generation != token.Generation ||
		ack.Action != token.Action || ack.OperationID != token.OperationID ||
		VerifyCheckpointFenceAcknowledgement(ack, w.id, w.publicKey) != nil ||
		ack.CommittedAtUnixMS > token.ExpiresAtUnixMS {
		return ErrCheckpointIntegrity
	}
	if old, exists := state.Operations[token.Generation]; exists {
		if old.TokenDigest != digest || !bytes.Equal(old.Ack.Signature, ack.Signature) {
			return ErrCheckpointConflict
		}
		return nil
	}
	if old, exists := index.OperationIDs[token.OperationID]; exists &&
		(old.Scope != token.Scope || old.Generation != token.Generation || old.TokenDigest != digest) {
		return ErrCheckpointConflict
	}
	if token.ExpectedFenceGeneration != state.Generation || token.Generation != state.Generation+1 ||
		token.ExpectedRevocationEpoch != state.RevocationEpoch ||
		token.PreviousFenceSHA256 != state.FenceHead ||
		!validFencePrimaryHeadLink(state, token.PrimaryHeadGeneration, token.PrimaryHeadSHA256) {
		return ErrCheckpointStale
	}
	state.Operations[token.Generation] = checkpointFenceWitnessOperation{TokenDigest: digest, Ack: cloneCheckpointFenceAck(ack)}
	index.OperationIDs[token.OperationID] = checkpointFenceWitnessOperationRef{Scope: token.Scope, Generation: token.Generation, TokenDigest: digest}
	state.Generation = token.Generation
	state.RevocationEpoch = token.ResultingRevocationEpoch
	state.FenceHead = digest
	state.PrimaryHeadGeneration = token.PrimaryHeadGeneration
	state.PrimaryHeadSHA256 = token.PrimaryHeadSHA256
	return nil
}

func verifyCheckpointFenceTokenSignature(token CheckpointFenceToken, publicKey ed25519.PublicKey) error {
	message, err := checkpointFenceTokenMessage(token)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		token.PrimaryKeyID != checkpointProviderKeyID(publicKey) ||
		len(token.Signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, token.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

func VerifyCheckpointFenceAcknowledgement(ack CheckpointFenceAcknowledgement, witnessID string, publicKey ed25519.PublicKey) error {
	if witnessID == "" || ack.WitnessID != witnessID || len(publicKey) != ed25519.PublicKeySize ||
		ack.WitnessKeyID != checkpointProviderKeyID(publicKey) ||
		ack.Generation == 0 || ack.OperationID == "" ||
		(ack.Action != CheckpointFenceFinalize && ack.Action != CheckpointFenceRevoke) ||
		ack.TokenSHA256 == ([sha256.Size]byte{}) || ack.CommittedAtUnixMS <= 0 ||
		len(ack.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, checkpointFenceAcknowledgementMessage(ack), ack.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

func checkpointFenceAcknowledgementMessage(ack CheckpointFenceAcknowledgement) []byte {
	var b bytes.Buffer
	io.WriteString(&b, "wedecent-checkpoint-fence-ack-v1\n")
	putFenceString(&b, ack.WitnessID)
	b.Write(ack.TokenSHA256[:])
	_ = json.NewEncoder(&b).Encode(struct {
		Generation uint64
		Action CheckpointFenceAction
		OperationID string
		WitnessKeyID string
		CommittedAtUnixMS int64
	}{ack.Generation, ack.Action, ack.OperationID, ack.WitnessKeyID, ack.CommittedAtUnixMS})
	return b.Bytes()
}

func putFenceString(b *bytes.Buffer, value string) {
	_ = json.NewEncoder(b).Encode(value)
}

func validFencePrimaryHeadLink(state interface{ }, generation uint64, digest [sha256.Size]byte) bool {
	switch current := state.(type) {
	case *checkpointFencePrimaryScopeState:
		if generation < current.PrimaryHeadGeneration {
			return false
		}
		if generation == current.PrimaryHeadGeneration {
			return digest == current.PrimaryHeadSHA256
		}
		return digest != current.PrimaryHeadSHA256
	case *checkpointFenceWitnessScopeState:
		if generation < current.PrimaryHeadGeneration {
			return false
		}
		if generation == current.PrimaryHeadGeneration {
			return digest == current.PrimaryHeadSHA256
		}
		return digest != current.PrimaryHeadSHA256
	default:
		return false
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func newCheckpointFencePrimaryIndex() *checkpointFencePrimaryIndex {
	return &checkpointFencePrimaryIndex{Scopes: make(map[CheckpointWitnessScope]*checkpointFencePrimaryScopeState), IDs: make(map[string]CheckpointWitnessScope)}
}

func newCheckpointFencePrimaryScope() *checkpointFencePrimaryScopeState {
	return &checkpointFencePrimaryScopeState{Operations: make(map[string]CheckpointFenceOperation)}
}

func newCheckpointFenceWitnessIndex() *checkpointFenceWitnessIndex {
	return &checkpointFenceWitnessIndex{
		Scopes: make(map[CheckpointWitnessScope]*checkpointFenceWitnessScopeState),
		OperationIDs: make(map[string]checkpointFenceWitnessOperationRef),
	}
}

func newCheckpointFenceWitnessScope() *checkpointFenceWitnessScopeState {
	return &checkpointFenceWitnessScopeState{Operations: make(map[uint64]checkpointFenceWitnessOperation)}
}

func cloneCheckpointFenceToken(token CheckpointFenceToken) CheckpointFenceToken {
	token.WitnessIDs = append([]string(nil), token.WitnessIDs...)
	token.Signature = append([]byte(nil), token.Signature...)
	return token
}

func cloneCheckpointFenceAck(ack CheckpointFenceAcknowledgement) CheckpointFenceAcknowledgement {
	ack.Signature = append([]byte(nil), ack.Signature...)
	return ack
}

func cloneCheckpointFenceAcks(acks []CheckpointFenceAcknowledgement) []CheckpointFenceAcknowledgement {
	out := make([]CheckpointFenceAcknowledgement, len(acks))
	for i := range acks {
		out[i] = cloneCheckpointFenceAck(acks[i])
	}
	return out
}

func replayCheckpointFenceLog(file *os.File, apply func(checkpointFenceDiskEvent) error) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.Join(ErrCheckpointFenceStore, err)
	}
	reader := bufio.NewReader(file)
	var offset int64
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > checkpointFenceLogMaxRecord {
			return ErrCheckpointIntegrity
		}
		if err == io.EOF && len(line) > 0 {
			if truncateErr := file.Truncate(offset); truncateErr != nil {
				return errors.Join(ErrCheckpointFenceStore, truncateErr)
			}
			if _, seekErr := file.Seek(0, io.SeekEnd); seekErr != nil {
				return errors.Join(ErrCheckpointFenceStore, seekErr)
			}
			if syncErr := file.Sync(); syncErr != nil {
				return errors.Join(ErrCheckpointFenceStore, syncErr)
			}
			return nil
		}
		if err != nil && err != io.EOF {
			return errors.Join(ErrCheckpointFenceStore, err)
		}
		if len(line) == 0 {
			break
		}
		if line[len(line)-1] != '\n' {
			return ErrCheckpointIntegrity
		}
		var event checkpointFenceDiskEvent
		if err := json.Unmarshal(bytes.TrimSpace(line), &event); err != nil {
			return errors.Join(ErrCheckpointIntegrity, err)
		}
		if err := apply(event); err != nil {
			return errors.Join(ErrCheckpointIntegrity, err)
		}
		offset += int64(len(line))
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return errors.Join(ErrCheckpointFenceStore, err)
	}
	return nil
}

func appendCheckpointFenceEvent(file *os.File, event checkpointFenceDiskEvent) error {
	payload, err := json.Marshal(event)
	if err != nil || len(payload)+1 > checkpointFenceLogMaxRecord {
		return errors.Join(ErrCheckpointFenceStore, err)
	}
	payload = append(payload, '\n')
	for len(payload) > 0 {
		n, writeErr := file.Write(payload)
		if writeErr != nil {
			return errors.Join(ErrCheckpointFenceStore, writeErr)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	if err := file.Sync(); err != nil {
		return errors.Join(ErrCheckpointFenceStore, err)
	}
	return nil
}

func withCheckpointFenceLog(ctx context.Context, path string, fn func(*os.File) error) error {
	if ctx == nil || path == "" {
		return ErrCheckpointFenceStore
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := openCheckpointFenceLog(path)
	if err != nil {
		return errors.Join(ErrCheckpointFenceStore, err)
	}
	defer file.Close()
	unlock, err := lockCheckpointFenceLog(ctx, file)
	if err != nil {
		return errors.Join(ErrCheckpointFenceStore, err)
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(file)
}


func sameCheckpointFenceToken(a, b CheckpointFenceToken) bool {
	aDigest, aErr := CheckpointFenceTokenDigest(a)
	bDigest, bErr := CheckpointFenceTokenDigest(b)
	return aErr == nil && bErr == nil && aDigest == bDigest && bytes.Equal(a.Signature, b.Signature)
}

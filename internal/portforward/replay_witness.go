package portforward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

var (
	ErrCheckpointQuorum              = errors.New("portforward: independent checkpoint witness quorum unavailable")
	ErrCheckpointWitnessDisagreement = errors.New("portforward: independent checkpoint witnesses disagree")
	ErrCheckpointWitnessRollback     = errors.New("portforward: historical checkpoint head rejected by witness")
)

type CheckpointWitnessScope struct {
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
type WitnessedReplayCheckpointProvider struct {
	Primary    ReplayCheckpointProvider
	PrimaryKey ed25519.PublicKey
	Witnesses  []CheckpointWitnessTrust
	Quorum     int
	Pending    CheckpointPendingStore
}

func (p *WitnessedReplayCheckpointProvider) Consume(ctx context.Context, request CheckpointRequest) (CheckpointResult, error) {
	if p == nil || p.Primary == nil || p.Pending == nil || len(p.PrimaryKey) != ed25519.PublicKeySize ||
		p.Quorum < 1 || p.Quorum > len(p.Witnesses) || !validWitnessSet(p.Witnesses, p.Quorum) {
		return CheckpointResult{}, ErrCheckpointUnavailable
	}
	existingPending, err := p.Pending.Begin(ctx, request)
	if err != nil {
		return CheckpointResult{}, err
	}
	result, err := p.Primary.Consume(ctx, request)
	if err != nil {
		return CheckpointResult{}, err
	}
	if err := VerifyCheckpointResult(result, request, p.PrimaryKey); err != nil {
		return CheckpointResult{}, err
	}
	if result.Disposition == CheckpointRecovered && !existingPending {
		return CheckpointResult{}, ErrCheckpointHistorical
	}
	receipts, err := p.commitWitnessQuorum(ctx, request, result.CheckpointReceipt, existingPending, result.Disposition)
	if err != nil {
		return CheckpointResult{}, err
	}
	if err := p.Pending.Resolve(ctx, request, result.CheckpointReceipt); err != nil {
		return CheckpointResult{}, err
	}
	acks, err := p.acknowledgeWitnessQuorum(ctx, request, result.CheckpointReceipt)
	if err != nil {
		return CheckpointResult{}, err
	}
	result.WitnessReceipts = receipts
	result.WitnessAcknowledgements = acks
	return result, nil
}

func (p *WitnessedReplayCheckpointProvider) Revoke(ctx context.Context, endpoint CheckpointEndpoint, next uint64) error {
	if p == nil || p.Primary == nil || p.Quorum < 1 || p.Quorum > len(p.Witnesses) || !validWitnessSet(p.Witnesses, p.Quorum) {
		return ErrCheckpointUnavailable
	}
	if !validCheckpointEndpoint(endpoint) || next <= endpoint.RevocationEpoch {
		return ErrCheckpointStale
	}
	primaryHead, err := p.Primary.Head(ctx, endpoint)
	if err != nil {
		return err
	}
	if err := VerifyCheckpointHead(primaryHead, endpoint, p.PrimaryKey); err != nil {
		return err
	}
	if next < primaryHead.RevocationEpoch {
		return ErrCheckpointStale
	}
	if next > primaryHead.RevocationEpoch {
		if err := p.Primary.Revoke(ctx, endpoint, next); err != nil {
			return err
		}
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
	if p == nil || p.Primary == nil || p.Quorum < 1 || p.Quorum > len(p.Witnesses) || !validWitnessSet(p.Witnesses, p.Quorum) {
		return CheckpointHead{}, ErrCheckpointUnavailable
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
		if r.err != nil || VerifyCheckpointWitnessHead(r.head, r.trust.ID, r.trust.PublicKey) != nil {
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

func (p *WitnessedReplayCheckpointProvider) acknowledgeWitnessQuorum(ctx context.Context, request CheckpointRequest, receipt CheckpointReceipt) ([]CheckpointWitnessAck, error) {
	type response struct {
		trust CheckpointWitnessTrust
		ack   CheckpointWitnessAck
		err   error
	}
	ch := make(chan response, len(p.Witnesses))
	for _, trust := range p.Witnesses {
		trust := trust
		go func() {
			ack, err := trust.Witness.Acknowledge(ctx, request, receipt)
			ch <- response{trust: trust, ack: ack, err: err}
		}()
	}
	acks := make([]CheckpointWitnessAck, 0, len(p.Witnesses))
	for range p.Witnesses {
		r := <-ch
		if r.err != nil || VerifyCheckpointWitnessAck(r.ack, r.trust.ID, r.trust.PublicKey) != nil ||
			r.ack.Scope != witnessScope(checkpointEndpointForConsumer(request)) ||
			r.ack.JTI != request.JTI || r.ack.RequestSHA256 != receipt.RequestSHA256 ||
			r.ack.PrimaryReceiptSHA256 != sha256.Sum256(checkpointReceiptMessage(receipt)) {
			continue
		}
		if r.ack.Status == "already_acknowledged" {
			return nil, ErrCheckpointHistorical
		}
		if r.ack.Status != "acknowledged" {
			continue
		}
		acks = append(acks, r.ack)
	}
	if len(acks) < p.Quorum {
		return nil, ErrCheckpointQuorum
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
	for range p.Witnesses {
		r := <-ch
		if r.err != nil || VerifyCheckpointWitnessHead(r.head, r.trust.ID, r.trust.PublicKey) != nil {
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

func VerifyCheckpointWitnessAck(ack CheckpointWitnessAck, witnessID string, publicKey ed25519.PublicKey) error {
	if witnessID == "" || ack.WitnessID != witnessID || len(publicKey) != ed25519.PublicKeySize ||
		ack.WitnessKeyID != checkpointProviderKeyID(publicKey) ||
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
	io.WriteString(&b, "wedecent-independent-witness-ack-v1\n")
	putWitnessString(&b, ack.WitnessID)
	putWitnessString(&b, ack.Scope.DeviceID)
	putWitnessString(&b, ack.Scope.AccountID)
	putWitnessString(&b, ack.Scope.OrganizationID)
	putWitnessString(&b, ack.JTI)
	b.Write(ack.RequestSHA256[:])
	b.Write(ack.PrimaryReceiptSHA256[:])
	putWitnessString(&b, ack.Status)
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
		a.RevocationEpoch == b.RevocationEpoch
}

func sameWitnessHead(a, b CheckpointWitnessHead) bool {
	return a.Scope == b.Scope && a.Generation == b.Generation && a.RecordHash == b.RecordHash &&
		a.PrimaryGeneration == b.PrimaryGeneration && a.PrimaryHead == b.PrimaryHead &&
		a.RevocationEpoch == b.RevocationEpoch
}

func checkpointWitnessRecordHash(receipt CheckpointWitnessReceipt) [sha256.Size]byte {
	receipt.RecordHash = [sha256.Size]byte{}
	return sha256.Sum256(checkpointWitnessReceiptMessage(receipt))
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
	for _, e := range []CheckpointEndpoint{request.Initiator, request.Destination} {
		if e.RevocationEpoch != w.revoked[witnessScope(e)] {
			return CheckpointWitnessReceipt{}, ErrCheckpointRevoked
		}
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
		PrimaryReceiptSHA256: digest, Status: status, WitnessKeyID: checkpointProviderKeyID(w.private.Public().(ed25519.PublicKey))}
	ack.Signature = ed25519.Sign(w.private, checkpointWitnessAckMessage(ack))
	return ack, nil
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
	if ledger == nil {
		ledger = &deterministicWitnessLedger{used: make(map[string][sha256.Size]byte)}
		w.ledgers[scope] = ledger
	}
	head := CheckpointWitnessHead{WitnessID: w.id, Scope: scope, Generation: ledger.generation, RecordHash: ledger.head,
		PrimaryGeneration: ledger.primaryGeneration, PrimaryHead: ledger.primaryHead, RevocationEpoch: ledger.revocationEpoch,
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

package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"

	"wedecent.com/wedecent/internal/identity"
)

type checkpointStored struct {
	requestHash [32]byte
	receipt     CheckpointReceipt
}
type checkpointLedgerKey struct{ device, account, organization string }
type checkpointLedger struct {
	generation uint64
	head       [32]byte
	used       map[string]checkpointStored
}
type deterministicCheckpointProvider struct {
	mu                                                 sync.Mutex
	private                                            ed25519.PrivateKey
	keyID                                              string
	members                                            map[string]CheckpointEndpoint
	ledgers                                            map[checkpointLedgerKey]*checkpointLedger
	available, crashBefore, crashAfter, corruptReceipt bool
	primaryDB                                          map[string]string
}

func newDeterministicCheckpointProvider(t *testing.T) *deterministicCheckpointProvider {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &deterministicCheckpointProvider{private: private, keyID: checkpointProviderKeyID(private.Public().(ed25519.PublicKey)),
		members: map[string]CheckpointEndpoint{}, ledgers: map[checkpointLedgerKey]*checkpointLedger{}, available: true, primaryDB: map[string]string{}}
}
func memberKey(e CheckpointEndpoint) string {
	return e.DeviceID + "|" + e.AccountID + "|" + e.OrganizationID
}
func (p *deterministicCheckpointProvider) register(e CheckpointEndpoint) { p.members[memberKey(e)] = e }

func (p *deterministicCheckpointProvider) Consume(ctx context.Context, request CheckpointRequest) (CheckpointResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckpointResult{}, err
	}
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return CheckpointResult{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.available {
		return CheckpointResult{}, ErrCheckpointUnavailable
	}
	initiator, iok := p.members[memberKey(request.Initiator)]
	destination, dok := p.members[memberKey(request.Destination)]
	if !iok || !dok || initiator.RevocationEpoch != request.Initiator.RevocationEpoch || destination.RevocationEpoch != request.Destination.RevocationEpoch {
		return CheckpointResult{}, ErrCheckpointRevoked
	}
	consumer, ok := checkpointConsumer(request)
	if !ok {
		return CheckpointResult{}, ErrCheckpointIntegrity
	}
	if p.crashBefore {
		p.crashBefore = false
		return CheckpointResult{}, ErrCheckpointUnavailable
	}
	key := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
	ledger := p.ledgers[key]
	if ledger == nil {
		ledger = &checkpointLedger{used: map[string]checkpointStored{}}
		p.ledgers[key] = ledger
	}
	if old, exists := ledger.used[request.JTI]; exists {
		if old.requestHash != fingerprint {
			return CheckpointResult{}, ErrCheckpointConflict
		}
		return SignCheckpointResult(p.private, CheckpointResult{CheckpointReceipt: cloneCheckpointReceipt(old.receipt), Disposition: CheckpointRecovered})
	}
	receipt := CheckpointReceipt{Version: checkpointVersion, DeviceID: consumer.DeviceID, AccountID: consumer.AccountID,
		OrganizationID: consumer.OrganizationID, JTI: request.JTI, AuthorizationSHA256: request.AuthorizationSHA256,
		RequestSHA256: fingerprint, Generation: ledger.generation + 1, PreviousHash: ledger.head, ProviderKeyID: p.keyID}
	receipt.RecordHash = checkpointRecordHash(receipt.PreviousHash, receipt.Generation, fingerprint)
	receipt, err = SignCheckpointReceipt(p.private, receipt)
	if err != nil {
		return CheckpointResult{}, err
	}
	if p.crashBefore {
		p.crashBefore = false
		return CheckpointResult{}, ErrCheckpointUnavailable
	}
	ledger.generation = receipt.Generation
	ledger.head = receipt.RecordHash
	ledger.used[request.JTI] = checkpointStored{fingerprint, cloneCheckpointReceipt(receipt)}
	p.primaryDB[request.JTI] = fmt.Sprint(receipt.Generation)
	if p.crashAfter {
		p.crashAfter = false
		return CheckpointResult{}, ErrCheckpointAmbiguous
	}
	if p.corruptReceipt {
		receipt.Signature = append([]byte(nil), receipt.Signature...)
		receipt.Signature[0] ^= 0xff
	}
	return SignCheckpointResult(p.private, CheckpointResult{CheckpointReceipt: receipt, Disposition: CheckpointCommitted})
}
func (p *deterministicCheckpointProvider) Recover(ctx context.Context, request CheckpointRequest) (CheckpointResult, error) {
	if err := ctx.Err(); err != nil {
		return CheckpointResult{}, err
	}
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return CheckpointResult{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.available {
		return CheckpointResult{}, ErrCheckpointUnavailable
	}
	consumer, ok := checkpointConsumer(request)
	if !ok {
		return CheckpointResult{}, ErrCheckpointIntegrity
	}
	key := checkpointLedgerKey{consumer.DeviceID, consumer.AccountID, consumer.OrganizationID}
	ledger := p.ledgers[key]
	if ledger == nil {
		return CheckpointResult{}, ErrCheckpointHistorical
	}
	stored, exists := ledger.used[request.JTI]
	if !exists {
		return CheckpointResult{}, ErrCheckpointHistorical
	}
	if stored.requestHash != fingerprint {
		return CheckpointResult{}, ErrCheckpointConflict
	}
	return SignCheckpointResult(p.private, CheckpointResult{CheckpointReceipt: cloneCheckpointReceipt(stored.receipt), Disposition: CheckpointRecovered})
}
func (p *deterministicCheckpointProvider) Revoke(ctx context.Context, e CheckpointEndpoint, next uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.available {
		return ErrCheckpointUnavailable
	}
	current, ok := p.members[memberKey(e)]
	if !ok || next <= current.RevocationEpoch {
		return ErrCheckpointStale
	}
	current.RevocationEpoch = next
	p.members[memberKey(e)] = current
	return nil
}
func (p *deterministicCheckpointProvider) Head(ctx context.Context, e CheckpointEndpoint) (CheckpointHead, error) {
	if err := ctx.Err(); err != nil {
		return CheckpointHead{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.available {
		return CheckpointHead{}, ErrCheckpointUnavailable
	}
	current, ok := p.members[memberKey(e)]
	if !ok {
		return CheckpointHead{}, ErrCheckpointRevoked
	}
	key := checkpointLedgerKey{e.DeviceID, e.AccountID, e.OrganizationID}
	ledger := p.ledgers[key]
	head := CheckpointHead{Version: checkpointVersion, DeviceID: e.DeviceID, AccountID: e.AccountID, OrganizationID: e.OrganizationID,
		ProviderKeyID: p.keyID, RevocationEpoch: current.RevocationEpoch}
	if ledger != nil {
		head.Generation = ledger.generation
		head.RecordHash = ledger.head
	}
	return SignCheckpointHead(p.private, head)
}
func cloneCheckpointReceipt(r CheckpointReceipt) CheckpointReceipt {
	r.Signature = append([]byte(nil), r.Signature...)
	return r
}
func cloneCheckpointLedger(l *checkpointLedger) *checkpointLedger {
	c := &checkpointLedger{generation: l.generation, head: l.head, used: map[string]checkpointStored{}}
	for k, v := range l.used {
		c.used[k] = checkpointStored{v.requestHash, cloneCheckpointReceipt(v.receipt)}
	}
	return c
}

func makeCheckpointFixture(t *testing.T, p *deterministicCheckpointProvider, accountA, accountB string) (CheckpointRequest, ed25519.PrivateKey, ed25519.PrivateKey, CheckpointEndpoint, CheckpointEndpoint) {
	t.Helper()
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	org := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	a := CheckpointEndpoint{DeviceID: identity.DeviceID(pubA), AccountID: accountA, OrganizationID: org}
	b := CheckpointEndpoint{DeviceID: identity.DeviceID(pubB), AccountID: accountB, OrganizationID: org}
	p.register(a)
	p.register(b)
	digest := sha256.Sum256([]byte("exact signed authorization bytes"))
	jti := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	req, err := SignCheckpointRequest(privA, CheckpointRequest{Initiator: a, Destination: b, ConsumingDeviceID: a.DeviceID, JTI: jti, AuthorizationSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	return req, privA, privB, a, b
}

func TestCheckpointConcurrentConsumptionAndExactRetry(t *testing.T) {
	p := newDeterministicCheckpointProvider(t)
	req, _, _, a, _ := makeCheckpointFixture(t, p, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	const n = 48
	var wg sync.WaitGroup
	receipts := make(chan CheckpointResult, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r, e := p.Consume(context.Background(), req); receipts <- r; errs <- e }()
	}
	wg.Wait()
	close(receipts)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first CheckpointResult
	committed := 0
	for r := range receipts {
		if r.Disposition == CheckpointCommitted {
			committed++
		}
		if first.Generation == 0 {
			first = r
		} else if first.Generation != r.Generation || first.RecordHash != r.RecordHash {
			t.Fatal("idempotent retries returned different receipts")
		}
	}
	if first.Generation != 1 {
		t.Fatalf("generation=%d", first.Generation)
	}
	if committed != 1 {
		t.Fatalf("new commits=%d, want exactly one", committed)
	}
	if err := VerifyCheckpointResult(first, req, p.private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	head, err := p.Head(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCheckpointHead(head, a, p.private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointConcurrentRevocationAndConsumption(t *testing.T) {
	p := newDeterministicCheckpointProvider(t)
	req, _, _, a, _ := makeCheckpointFixture(t, p, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	start := make(chan struct{})
	var wg sync.WaitGroup
	var consumeErr, revokeErr error
	wg.Add(2)
	go func() { defer wg.Done(); <-start; _, consumeErr = p.Consume(context.Background(), req) }()
	go func() { defer wg.Done(); <-start; revokeErr = p.Revoke(context.Background(), a, 1) }()
	close(start)
	wg.Wait()
	if revokeErr != nil {
		t.Fatal(revokeErr)
	}
	if consumeErr != nil && !errors.Is(consumeErr, ErrCheckpointRevoked) {
		t.Fatalf("consume: %v", consumeErr)
	}
	if _, err := p.Consume(context.Background(), req); !errors.Is(err, ErrCheckpointRevoked) {
		t.Fatalf("old epoch accepted after revoke: %v", err)
	}
}

func TestCheckpointCrashBeforeAfterCommitAndLostResponseRetry(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprintf("after_commit_%t", after), func(t *testing.T) {
			p := newDeterministicCheckpointProvider(t)
			req, _, _, _, _ := makeCheckpointFixture(t, p, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
			p.crashBefore = !after
			p.crashAfter = after
			_, err := p.Consume(context.Background(), req)
			if after && !errors.Is(err, ErrCheckpointAmbiguous) {
				t.Fatalf("want ambiguous: %v", err)
			}
			if !after && !errors.Is(err, ErrCheckpointUnavailable) {
				t.Fatalf("want precommit failure: %v", err)
			}
			r, err := p.Consume(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if r.Generation != 1 {
				t.Fatalf("generation=%d", r.Generation)
			}
			wantDisposition := CheckpointCommitted
			if after {
				wantDisposition = CheckpointRecovered
			}
			if r.Disposition != wantDisposition {
				t.Fatalf("disposition=%q, want %q", r.Disposition, wantDisposition)
			}
			if err := VerifyCheckpointResult(r, req, p.private.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckpointConflictingJTIAndForgedReceipt(t *testing.T) {
	p := newDeterministicCheckpointProvider(t)
	req, priv, _, _, _ := makeCheckpointFixture(t, p, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	r, err := p.Consume(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	conflict := req
	conflict.AuthorizationSHA256 = sha256.Sum256([]byte("different capability"))
	conflict, err = SignCheckpointRequest(priv, conflict)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Consume(context.Background(), conflict); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("conflict: %v", err)
	}
	tamperedDisposition := r
	tamperedDisposition.Disposition = CheckpointRecovered
	if err := VerifyCheckpointResult(tamperedDisposition, req, p.private.Public().(ed25519.PublicKey)); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("unsigned disposition change accepted: %v", err)
	}
	r.Signature[0] ^= 0xff
	if err := VerifyCheckpointResult(r, req, p.private.Public().(ed25519.PublicKey)); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("forged result signature: %v", err)
	}
	r.CheckpointReceipt.Signature[0] ^= 0xff
	if err := VerifyCheckpointReceipt(r.CheckpointReceipt, req, p.private.Public().(ed25519.PublicKey)); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("forged receipt: %v", err)
	}
}

func TestCheckpointUnavailableAndMalformedRequestFailClosed(t *testing.T) {
	p := newDeterministicCheckpointProvider(t)
	req, _, _, _, _ := makeCheckpointFixture(t, p, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	p.available = false
	if _, err := p.Consume(context.Background(), req); !errors.Is(err, ErrCheckpointUnavailable) {
		t.Fatal(err)
	}
	p.available = true
	req.Destination.AccountID = "not-a-canonical-account"
	if _, err := p.Consume(context.Background(), req); !errors.Is(err, ErrCheckpointIntegrity) {
		t.Fatalf("malformed identity accepted: %v", err)
	}
}

func TestCheckpointCompletePrimaryDatabaseRestoreDoesNotRestoreCheckpoint(t *testing.T) {
	p := newDeterministicCheckpointProvider(t)
	req, _, _, _, _ := makeCheckpointFixture(t, p, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	if _, err := p.Consume(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	primarySnapshot := map[string]string{}
	for k, v := range p.primaryDB {
		primarySnapshot[k] = v
	}
	// Simulate restoring every row in the primary database to an earlier snapshot.
	p.primaryDB = map[string]string{"old-snapshot": "restored"}
	result, err := p.Consume(context.Background(), req)
	if err != nil {
		t.Fatalf("checkpoint should return exact durable receipt after primary restore: %v", err)
	}
	if result.Disposition != CheckpointRecovered {
		t.Fatalf("restored-primary retry disposition=%q; must never appear as a new authorization", result.Disposition)
	}
	if err := VerifyCheckpointResult(result, req, p.private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if _, ok := primarySnapshot[req.JTI]; !ok {
		t.Fatal("fixture did not snapshot primary transaction")
	}
}

func TestCheckpointCrossDeviceAndCrossAccountIsolation(t *testing.T) {
	p := newDeterministicCheckpointProvider(t)
	req, privA, privB, a, b := makeCheckpointFixture(t, p, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	if _, err := p.Consume(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	peerRequest := req
	peerRequest.ConsumingDeviceID = b.DeviceID
	peerRequest, err := SignCheckpointRequest(privB, peerRequest)
	if err != nil {
		t.Fatal(err)
	}
	peerReceipt, err := p.Consume(context.Background(), peerRequest)
	if err != nil {
		t.Fatal(err)
	}
	if peerReceipt.Generation != 1 || peerReceipt.DeviceID != b.DeviceID {
		t.Fatal("device B did not receive an independent replay namespace")
	}
	headA, err := p.Head(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if headA.Generation != 1 {
		t.Fatalf("device A generation=%d", headA.Generation)
	}
	otherAccount := req
	otherAccount.Initiator.AccountID = "33333333-3333-4333-8333-333333333333"
	otherAccount, err = SignCheckpointRequest(privA, otherAccount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Consume(context.Background(), otherAccount); !errors.Is(err, ErrCheckpointRevoked) {
		t.Fatalf("cross-account membership bypass: %v", err)
	}
}

func TestCheckpointProviderCompromiseRequiresIndependentWitness(t *testing.T) {
	p := newDeterministicCheckpointProvider(t)
	req, priv, _, _, _ := makeCheckpointFixture(t, p, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	first, err := p.Consume(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	key := checkpointLedgerKey{req.Initiator.DeviceID, req.Initiator.AccountID, req.Initiator.OrganizationID}
	snapshot := cloneCheckpointLedger(p.ledgers[key])
	secondReq := req
	secondReq.JTI = base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	secondReq, err = SignCheckpointRequest(priv, secondReq)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Consume(context.Background(), secondReq)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate provider compromise restoring its own ledger and retaining its signing key.
	p.ledgers[key] = snapshot
	replayed, err := p.Consume(context.Background(), secondReq)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Generation != second.Generation || replayed.Disposition != CheckpointCommitted || VerifyCheckpointResult(replayed, secondReq, p.private.Public().(ed25519.PublicKey)) != nil {
		t.Fatal("fixture should demonstrate that a compromised single provider can replay its own valid signed history")
	}
	if first.Generation != 1 {
		t.Fatal("bad fixture")
	}
}

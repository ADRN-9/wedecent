package portforward

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"wedecent.com/wedecent/internal/identity"
)

var (
	ErrCheckpointUnavailable = errors.New("portforward: checkpoint authority unavailable")
	ErrCheckpointReplay      = errors.New("portforward: checkpoint JTI already consumed")
	ErrCheckpointConflict    = errors.New("portforward: checkpoint JTI reused with conflicting request")
	ErrCheckpointRevoked     = errors.New("portforward: checkpoint endpoint membership or revocation rejected")
	ErrCheckpointIntegrity   = errors.New("portforward: checkpoint receipt or chain integrity failure")
	ErrCheckpointAmbiguous   = errors.New("portforward: checkpoint commit outcome is ambiguous")
	ErrCheckpointStale       = errors.New("portforward: checkpoint generation or revocation epoch is stale")
)

const checkpointVersion uint32 = 1
const checkpointRequestDomain = "wedecent-replay-checkpoint-request-v1"
const checkpointReceiptDomain = "wedecent-replay-checkpoint-receipt-v1"
const checkpointHeadDomain = "wedecent-replay-checkpoint-head-v1"

// CheckpointEndpoint binds an Ed25519 device to immutable account and organization UUIDs.
type CheckpointEndpoint struct {
	DeviceID        string
	AccountID       string
	OrganizationID  string
	RevocationEpoch uint64
}

// CheckpointRequest is signed by the consuming endpoint. The peer is bound by
// the separately verified forwarding capability; both memberships are checked by the provider.
type CheckpointRequest struct {
	Initiator           CheckpointEndpoint
	Destination         CheckpointEndpoint
	ConsumingDeviceID   string
	JTI                 string
	AuthorizationSHA256 [sha256.Size]byte
	DevicePublicKey     ed25519.PublicKey
	DeviceSignature     []byte
}

// CheckpointReceipt is an authenticated durable commit receipt.
type CheckpointReceipt struct {
	Version             uint32
	DeviceID            string
	AccountID           string
	OrganizationID      string
	JTI                 string
	AuthorizationSHA256 [sha256.Size]byte
	RequestSHA256       [sha256.Size]byte
	Generation          uint64
	PreviousHash        [sha256.Size]byte
	RecordHash          [sha256.Size]byte
	ProviderKeyID       string
	Signature           []byte
}

// CheckpointHead is an authenticated recovery/reconciliation result.
type CheckpointHead struct {
	Version         uint32
	DeviceID        string
	AccountID       string
	OrganizationID  string
	Generation      uint64
	RecordHash      [sha256.Size]byte
	RevocationEpoch uint64
	ProviderKeyID   string
	Signature       []byte
}

// CheckpointDisposition distinguishes a new commit from recovery of a prior commit.
type CheckpointDisposition string

const (
	CheckpointCommitted CheckpointDisposition = "committed"
	CheckpointRecovered CheckpointDisposition = "recovered"
)

// CheckpointResult never turns an idempotent retry into a second authorization.
// Recovered results may resolve only a locally recorded pending operation; otherwise fail closed.
type CheckpointResult struct {
	CheckpointReceipt
	Disposition             CheckpointDisposition
	Signature               []byte
	WitnessReceipts         []CheckpointWitnessReceipt `json:"witness_receipts,omitempty"`
	WitnessAcknowledgements []CheckpointWitnessAck     `json:"witness_acknowledgements,omitempty"`
}

// ReplayCheckpointProvider implementations must serialize Consume and Revoke
// against the same durable state. Consume commits before returning. Ambiguous
// outcomes are retried with the exact same request; local replay fallback is forbidden.
type ReplayCheckpointProvider interface {
	Consume(context.Context, CheckpointRequest) (CheckpointResult, error)
	Revoke(context.Context, CheckpointEndpoint, uint64) error
	Head(context.Context, CheckpointEndpoint) (CheckpointHead, error)
}

// SignCheckpointRequest signs every endpoint, account, organization, epoch, JTI and digest field.
func SignCheckpointRequest(signer crypto.Signer, request CheckpointRequest) (CheckpointRequest, error) {
	if signer == nil {
		return CheckpointRequest{}, ErrCheckpointIntegrity
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return CheckpointRequest{}, ErrCheckpointIntegrity
	}
	request.DevicePublicKey = append(ed25519.PublicKey(nil), publicKey...)
	message, err := checkpointRequestMessage(request)
	if err != nil {
		return CheckpointRequest{}, err
	}
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return CheckpointRequest{}, ErrCheckpointIntegrity
	}
	request.DeviceSignature = append([]byte(nil), signature...)
	return request, nil
}

// VerifyCheckpointReceipt validates provider authenticity and exact-request binding.
func cloneCheckpointReceiptValue(receipt CheckpointReceipt) CheckpointReceipt {
	receipt.Signature = append([]byte(nil), receipt.Signature...)
	return receipt
}

func VerifyCheckpointReceipt(receipt CheckpointReceipt, request CheckpointRequest, providerKey ed25519.PublicKey) error {
	endpoint, ok := checkpointConsumer(request)
	if !ok || len(providerKey) != ed25519.PublicKeySize || receipt.Version != checkpointVersion ||
		receipt.DeviceID != endpoint.DeviceID || receipt.AccountID != endpoint.AccountID ||
		receipt.OrganizationID != endpoint.OrganizationID || receipt.JTI != request.JTI ||
		receipt.AuthorizationSHA256 != request.AuthorizationSHA256 || receipt.Generation == 0 ||
		receipt.ProviderKeyID != checkpointProviderKeyID(providerKey) || len(receipt.Signature) != ed25519.SignatureSize {
		return ErrCheckpointIntegrity
	}
	requestHash, err := CheckpointRequestFingerprint(request)
	if err != nil || receipt.RequestSHA256 != requestHash ||
		receipt.RecordHash != checkpointRecordHash(receipt.PreviousHash, receipt.Generation, requestHash) {
		return ErrCheckpointIntegrity
	}
	if !ed25519.Verify(providerKey, checkpointReceiptMessage(receipt), receipt.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

// VerifyCheckpointResult verifies the receipt and requires an explicit known disposition.
func VerifyCheckpointResult(result CheckpointResult, request CheckpointRequest, providerKey ed25519.PublicKey) error {
	if result.Disposition != CheckpointCommitted && result.Disposition != CheckpointRecovered {
		return ErrCheckpointIntegrity
	}
	if err := VerifyCheckpointReceipt(result.CheckpointReceipt, request, providerKey); err != nil {
		return err
	}
	if len(result.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(providerKey, checkpointResultMessage(result), result.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

// SignCheckpointResult authenticates the response disposition without mutating the durable receipt.
func SignCheckpointResult(signer ed25519.PrivateKey, result CheckpointResult) (CheckpointResult, error) {
	if len(signer) != ed25519.PrivateKeySize ||
		result.ProviderKeyID != checkpointProviderKeyID(signer.Public().(ed25519.PublicKey)) ||
		(result.Disposition != CheckpointCommitted && result.Disposition != CheckpointRecovered) {
		return CheckpointResult{}, ErrCheckpointIntegrity
	}
	result.Signature = ed25519.Sign(signer, checkpointResultMessage(result))
	return result, nil
}

func VerifyCheckpointHead(head CheckpointHead, endpoint CheckpointEndpoint, providerKey ed25519.PublicKey) error {
	if len(providerKey) != ed25519.PublicKeySize || head.Version != checkpointVersion ||
		head.DeviceID != endpoint.DeviceID || head.AccountID != endpoint.AccountID ||
		head.OrganizationID != endpoint.OrganizationID || head.RevocationEpoch < endpoint.RevocationEpoch ||
		head.ProviderKeyID != checkpointProviderKeyID(providerKey) || len(head.Signature) != ed25519.SignatureSize {
		return ErrCheckpointIntegrity
	}
	if head.Generation == 0 && head.RecordHash != ([sha256.Size]byte{}) {
		return ErrCheckpointIntegrity
	}
	if !ed25519.Verify(providerKey, checkpointHeadMessage(head), head.Signature) {
		return ErrCheckpointIntegrity
	}
	return nil
}

func checkpointConsumer(request CheckpointRequest) (CheckpointEndpoint, bool) {
	switch request.ConsumingDeviceID {
	case request.Initiator.DeviceID:
		return request.Initiator, true
	case request.Destination.DeviceID:
		return request.Destination, true
	default:
		return CheckpointEndpoint{}, false
	}
}

func checkpointRequestMessage(request CheckpointRequest) ([]byte, error) {
	if !validCheckpointEndpoint(request.Initiator) || !validCheckpointEndpoint(request.Destination) ||
		request.Initiator.DeviceID == request.Destination.DeviceID ||
		request.Initiator.OrganizationID != request.Destination.OrganizationID ||
		(request.ConsumingDeviceID != request.Initiator.DeviceID && request.ConsumingDeviceID != request.Destination.DeviceID) ||
		!deviceIDPattern.MatchString(request.ConsumingDeviceID) || !jtiPattern.MatchString(request.JTI) ||
		request.AuthorizationSHA256 == ([sha256.Size]byte{}) ||
		len(request.DevicePublicKey) != ed25519.PublicKeySize ||
		identity.DeviceID(request.DevicePublicKey) != request.ConsumingDeviceID {
		return nil, ErrCheckpointIntegrity
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
	putEndpoint := func(endpoint CheckpointEndpoint) error {
		for _, value := range []string{endpoint.DeviceID, endpoint.AccountID, endpoint.OrganizationID} {
			if err := putString(value); err != nil {
				return err
			}
		}
		return binary.Write(&b, binary.BigEndian, endpoint.RevocationEpoch)
	}
	if err := putString(checkpointRequestDomain); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, checkpointVersion); err != nil {
		return nil, err
	}
	if err := putEndpoint(request.Initiator); err != nil {
		return nil, err
	}
	if err := putEndpoint(request.Destination); err != nil {
		return nil, err
	}
	if err := putString(request.ConsumingDeviceID); err != nil {
		return nil, err
	}
	if err := putString(request.JTI); err != nil {
		return nil, err
	}
	b.Write(request.AuthorizationSHA256[:])
	b.Write(request.DevicePublicKey)
	return b.Bytes(), nil
}

func CheckpointRequestFingerprint(request CheckpointRequest) ([sha256.Size]byte, error) {
	message, err := checkpointRequestMessage(request)
	if err != nil || len(request.DeviceSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(request.DevicePublicKey, message, request.DeviceSignature) {
		return [sha256.Size]byte{}, ErrCheckpointIntegrity
	}
	return sha256.Sum256(message), nil
}

func validCheckpointEndpoint(endpoint CheckpointEndpoint) bool {
	return deviceIDPattern.MatchString(endpoint.DeviceID) && canonicalUUID(endpoint.AccountID) &&
		canonicalUUID(endpoint.OrganizationID)
}

func canonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}

func checkpointRecordHash(previous [sha256.Size]byte, generation uint64, requestHash [sha256.Size]byte) [sha256.Size]byte {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], generation)
	input := make([]byte, 0, len(previous)+len(counter)+len(requestHash))
	input = append(input, previous[:]...)
	input = append(input, counter[:]...)
	input = append(input, requestHash[:]...)
	return sha256.Sum256(input)
}

func checkpointReceiptMessage(receipt CheckpointReceipt) []byte {
	var b bytes.Buffer
	io.WriteString(&b, checkpointReceiptDomain+"\n")
	binary.Write(&b, binary.BigEndian, receipt.Version)
	for _, value := range []string{receipt.DeviceID, receipt.AccountID, receipt.OrganizationID, receipt.JTI, receipt.ProviderKeyID} {
		binary.Write(&b, binary.BigEndian, uint32(len(value)))
		io.WriteString(&b, value)
	}
	binary.Write(&b, binary.BigEndian, receipt.Generation)
	b.Write(receipt.AuthorizationSHA256[:])
	b.Write(receipt.RequestSHA256[:])
	b.Write(receipt.PreviousHash[:])
	b.Write(receipt.RecordHash[:])
	return b.Bytes()
}

func checkpointResultMessage(result CheckpointResult) []byte {
	var b bytes.Buffer
	io.WriteString(&b, "wedecent-replay-checkpoint-result-v1\n")
	binary.Write(&b, binary.BigEndian, uint32(len(result.ProviderKeyID)))
	io.WriteString(&b, result.ProviderKeyID)
	binary.Write(&b, binary.BigEndian, uint32(len(result.Disposition)))
	io.WriteString(&b, string(result.Disposition))
	receiptDigest := sha256.Sum256(checkpointReceiptMessage(result.CheckpointReceipt))
	b.Write(receiptDigest[:])
	return b.Bytes()
}

func checkpointHeadMessage(head CheckpointHead) []byte {
	var b bytes.Buffer
	io.WriteString(&b, checkpointHeadDomain+"\n")
	binary.Write(&b, binary.BigEndian, head.Version)
	for _, value := range []string{head.DeviceID, head.AccountID, head.OrganizationID, head.ProviderKeyID} {
		binary.Write(&b, binary.BigEndian, uint32(len(value)))
		io.WriteString(&b, value)
	}
	binary.Write(&b, binary.BigEndian, head.Generation)
	binary.Write(&b, binary.BigEndian, head.RevocationEpoch)
	b.Write(head.RecordHash[:])
	return b.Bytes()
}

func checkpointProviderKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "ed25519-" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func SignCheckpointReceipt(signer ed25519.PrivateKey, receipt CheckpointReceipt) (CheckpointReceipt, error) {
	if len(signer) != ed25519.PrivateKeySize || receipt.ProviderKeyID != checkpointProviderKeyID(signer.Public().(ed25519.PublicKey)) {
		return CheckpointReceipt{}, fmt.Errorf("%w: invalid provider signing key", ErrCheckpointIntegrity)
	}
	receipt.Signature = ed25519.Sign(signer, checkpointReceiptMessage(receipt))
	return receipt, nil
}

func SignCheckpointHead(signer ed25519.PrivateKey, head CheckpointHead) (CheckpointHead, error) {
	if len(signer) != ed25519.PrivateKeySize || head.ProviderKeyID != checkpointProviderKeyID(signer.Public().(ed25519.PublicKey)) {
		return CheckpointHead{}, fmt.Errorf("%w: invalid provider signing key", ErrCheckpointIntegrity)
	}
	head.Signature = ed25519.Sign(signer, checkpointHeadMessage(head))
	return head, nil
}

func CheckpointReceiptDigest(receipt CheckpointReceipt) string {
	digest := sha256.Sum256(checkpointReceiptMessage(receipt))
	return hex.EncodeToString(digest[:])
}

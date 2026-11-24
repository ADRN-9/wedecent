package portforward

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"wedecent.com/wedecent/internal/identity"
)

func TestSharedCheckpointCryptoGoldenVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/portforward/checkpoint_crypto_vectors.json")
	if err != nil { t.Fatal(err) }
	var vector struct {
		Request struct {
			Initiator CheckpointEndpoint `json:"initiator"`
			Destination CheckpointEndpoint `json:"destination"`
			ConsumingDeviceID string `json:"consuming_device_id"`
			JTI string `json:"jti"`
			AuthorizationSHA256 string `json:"authorization_sha256"`
			DevicePublicKeyHex string `json:"device_public_key_hex"`
			MessageHex string `json:"message_hex"`
			FingerprintSHA256 string `json:"fingerprint_sha256"`
			OperationID string `json:"operation_id"`
		} `json:"request"`
		Receipt struct {
			Version uint32 `json:"version"`
			DeviceID, AccountID, OrganizationID, JTI, ProviderKeyID string
			Generation uint64 `json:"generation"`
			AuthorizationSHA256, RequestSHA256, PreviousHash, RecordHash string
			MessageHex string `json:"message_hex"`
		} `json:"primary_receipt"`
		Head struct {
			Version uint32 `json:"version"`
			DeviceID, AccountID, OrganizationID, ProviderKeyID string
			Generation, RevocationEpoch uint64
			RecordHash, MessageHex string
		} `json:"primary_head"`
		Ack struct {
			WitnessID string `json:"witness_id"`
			Scope CheckpointWitnessScope `json:"scope"`
			JTI, RequestSHA256, PrimaryReceiptSHA256, Decision, WitnessKeyID string
			MessageHex string `json:"message_hex"`
		} `json:"witness_ack"`
		WitnessHead struct {
			WitnessID string `json:"witness_id"`
			Scope CheckpointWitnessScope `json:"scope"`
			Generation uint64 `json:"generation"`
			RecordHash string `json:"record_hash"`
			PrimaryGeneration uint64 `json:"primary_generation"`
			PrimaryHead string `json:"primary_head"`
			RevocationEpoch uint64 `json:"revocation_epoch"`
			WitnessKeyID string `json:"witness_key_id"`
			MessageHex string `json:"message_hex"`
		} `json:"witness_head"`
		Canonical struct {
			Value map[string]any `json:"value"`
			CanonicalJSON string `json:"canonical_json"`
			SHA256 string `json:"sha256"`
		} `json:"canonical_payload"`
	}
	if err := json.Unmarshal(data, &vector); err != nil { t.Fatal(err) }
	decode := func(value string) []byte {
		t.Helper()
		b, err := hex.DecodeString(value)
		if err != nil { t.Fatal(err) }
		return b
	}
	requestKey := decode(vector.Request.DevicePublicKeyHex)
	if identity.DeviceID(requestKey) != vector.Request.ConsumingDeviceID { t.Fatal("golden request device identity mismatch") }
	auth := decode(vector.Request.AuthorizationSHA256)
	var authorization [sha256.Size]byte
	copy(authorization[:], auth)
	request := CheckpointRequest{
		Initiator: vector.Request.Initiator, Destination: vector.Request.Destination,
		ConsumingDeviceID: vector.Request.ConsumingDeviceID, JTI: vector.Request.JTI,
		AuthorizationSHA256: authorization, DevicePublicKey: requestKey,
	}
	message, err := checkpointRequestMessage(request)
	if err != nil { t.Fatal(err) }
	if hex.EncodeToString(message) != vector.Request.MessageHex { t.Fatal("checkpoint request encoding differs from shared vector") }
	fingerprint := sha256.Sum256(message)
	if hex.EncodeToString(fingerprint[:]) != vector.Request.FingerprintSHA256 { t.Fatal("checkpoint request fingerprint differs from shared vector") }
	operationID, err := checkpointOperationID(request)
	if err != nil || operationID != vector.Request.OperationID { t.Fatalf("operation ID=%s err=%v", operationID, err) }

	receipt := CheckpointReceipt{
		Version: vector.Receipt.Version, DeviceID: vector.Receipt.DeviceID,
		AccountID: vector.Receipt.AccountID, OrganizationID: vector.Receipt.OrganizationID,
		JTI: vector.Receipt.JTI, ProviderKeyID: vector.Receipt.ProviderKeyID,
		Generation: vector.Receipt.Generation,
	}
	copy(receipt.AuthorizationSHA256[:], decode(vector.Receipt.AuthorizationSHA256))
	copy(receipt.RequestSHA256[:], decode(vector.Receipt.RequestSHA256))
	copy(receipt.PreviousHash[:], decode(vector.Receipt.PreviousHash))
	copy(receipt.RecordHash[:], decode(vector.Receipt.RecordHash))
	if got := hex.EncodeToString(checkpointReceiptMessage(receipt)); got != vector.Receipt.MessageHex { t.Fatal("primary receipt encoding differs from shared vector") }

	head := CheckpointHead{Version: vector.Head.Version, DeviceID: vector.Head.DeviceID, AccountID: vector.Head.AccountID,
		OrganizationID: vector.Head.OrganizationID, ProviderKeyID: vector.Head.ProviderKeyID,
		Generation: vector.Head.Generation, RevocationEpoch: vector.Head.RevocationEpoch}
	copy(head.RecordHash[:], decode(vector.Head.RecordHash))
	if got := hex.EncodeToString(checkpointHeadMessage(head)); got != vector.Head.MessageHex { t.Fatal("primary head encoding differs from shared vector") }

	ack := CheckpointWitnessAck{WitnessID: vector.Ack.WitnessID, Scope: vector.Ack.Scope, JTI: vector.Ack.JTI,
		Decision: vector.Ack.Decision, WitnessKeyID: vector.Ack.WitnessKeyID}
	copy(ack.RequestSHA256[:], decode(vector.Ack.RequestSHA256))
	copy(ack.PrimaryReceiptSHA256[:], decode(vector.Ack.PrimaryReceiptSHA256))
	if got := hex.EncodeToString(checkpointWitnessAckMessage(ack)); got != vector.Ack.MessageHex { t.Fatal("witness acknowledgement encoding differs from shared vector") }

	witnessHead := CheckpointWitnessHead{WitnessID: vector.WitnessHead.WitnessID, Scope: vector.WitnessHead.Scope,
		Generation: vector.WitnessHead.Generation, PrimaryGeneration: vector.WitnessHead.PrimaryGeneration,
		RevocationEpoch: vector.WitnessHead.RevocationEpoch, WitnessKeyID: vector.WitnessHead.WitnessKeyID}
	copy(witnessHead.RecordHash[:], decode(vector.WitnessHead.RecordHash))
	copy(witnessHead.PrimaryHead[:], decode(vector.WitnessHead.PrimaryHead))
	if got := hex.EncodeToString(checkpointWitnessHeadMessage(witnessHead)); got != vector.WitnessHead.MessageHex { t.Fatal("witness head encoding differs from shared vector") }

	canonical, err := json.Marshal(vector.Canonical.Value)
	if err != nil { t.Fatal(err) }
	if string(canonical) != vector.Canonical.CanonicalJSON { t.Fatalf("canonical JSON=%s", canonical) }
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != vector.Canonical.SHA256 { t.Fatal("canonical payload digest differs from shared vector") }
}

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
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]any
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	object := func(value any) map[string]any {
		t.Helper()
		result, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("expected JSON object, got %T", value)
		}
		return result
	}
	stringField := func(value map[string]any, key string) string {
		t.Helper()
		result, ok := value[key].(string)
		if !ok {
			t.Fatalf("expected string field %q", key)
		}
		return result
	}
	uintField := func(value map[string]any, key string) uint64 {
		t.Helper()
		result, ok := value[key].(float64)
		if !ok || result < 0 || result != float64(uint64(result)) {
			t.Fatalf("expected uint field %q", key)
		}
		return uint64(result)
	}
	decode := func(value string) []byte {
		t.Helper()
		result, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	hexBytes := func(value []byte) string { return hex.EncodeToString(value) }

	requestVector := object(vector["request"])
	initiatorVector := object(requestVector["initiator"])
	destinationVector := object(requestVector["destination"])
	requestKey := decode(stringField(requestVector, "device_public_key_hex"))
	consumingDeviceID := stringField(requestVector, "consuming_device_id")
	if identity.DeviceID(requestKey) != consumingDeviceID {
		t.Fatal("golden request device identity mismatch")
	}
	var authorization [sha256.Size]byte
	copy(authorization[:], decode(stringField(requestVector, "authorization_sha256")))
	request := CheckpointRequest{
		Initiator: CheckpointEndpoint{
			DeviceID: stringField(initiatorVector, "device_id"),
			AccountID: stringField(initiatorVector, "account_id"),
			OrganizationID: stringField(initiatorVector, "organization_id"),
			RevocationEpoch: uintField(initiatorVector, "revocation_epoch"),
		},
		Destination: CheckpointEndpoint{
			DeviceID: stringField(destinationVector, "device_id"),
			AccountID: stringField(destinationVector, "account_id"),
			OrganizationID: stringField(destinationVector, "organization_id"),
			RevocationEpoch: uintField(destinationVector, "revocation_epoch"),
		},
		ConsumingDeviceID: consumingDeviceID,
		JTI: stringField(requestVector, "jti"),
		AuthorizationSHA256: authorization,
		DevicePublicKey: requestKey,
	}
	requestMessage, err := checkpointRequestMessage(request)
	if err != nil {
		t.Fatal(err)
	}
	if hexBytes(requestMessage) != stringField(requestVector, "message_hex") {
		t.Fatal("checkpoint request encoding differs from shared vector")
	}
	requestHash := sha256.Sum256(requestMessage)
	if hexBytes(requestHash[:]) != stringField(requestVector, "fingerprint_sha256") {
		t.Fatal("checkpoint request fingerprint differs from shared vector")
	}
	operationID, err := checkpointOperationID(request)
	if err != nil || operationID != stringField(requestVector, "operation_id") {
		t.Fatalf("operation ID=%s err=%v", operationID, err)
	}

	receiptVector := object(vector["primary_receipt"])
	receipt := CheckpointReceipt{
		Version: uint32(uintField(receiptVector, "version")),
		DeviceID: stringField(receiptVector, "device_id"),
		AccountID: stringField(receiptVector, "account_id"),
		OrganizationID: stringField(receiptVector, "organization_id"),
		JTI: stringField(receiptVector, "jti"),
		ProviderKeyID: stringField(receiptVector, "provider_key_id"),
		Generation: uintField(receiptVector, "generation"),
	}
	copy(receipt.AuthorizationSHA256[:], decode(stringField(receiptVector, "authorization_sha256")))
	copy(receipt.RequestSHA256[:], decode(stringField(receiptVector, "request_sha256")))
	copy(receipt.PreviousHash[:], decode(stringField(receiptVector, "previous_hash")))
	copy(receipt.RecordHash[:], decode(stringField(receiptVector, "record_hash")))
	if hexBytes(checkpointReceiptMessage(receipt)) != stringField(receiptVector, "message_hex") {
		t.Fatal("primary receipt encoding differs from shared vector")
	}

	headVector := object(vector["primary_head"])
	head := CheckpointHead{
		Version: uint32(uintField(headVector, "version")),
		DeviceID: stringField(headVector, "device_id"),
		AccountID: stringField(headVector, "account_id"),
		OrganizationID: stringField(headVector, "organization_id"),
		ProviderKeyID: stringField(headVector, "provider_key_id"),
		Generation: uintField(headVector, "generation"),
		RevocationEpoch: uintField(headVector, "revocation_epoch"),
	}
	copy(head.RecordHash[:], decode(stringField(headVector, "record_hash")))
	if hexBytes(checkpointHeadMessage(head)) != stringField(headVector, "message_hex") {
		t.Fatal("primary head encoding differs from shared vector")
	}

	ackVector := object(vector["witness_ack"])
	ackScope := object(ackVector["scope"])
	ack := CheckpointWitnessAck{
		WitnessID: stringField(ackVector, "witness_id"),
		Scope: CheckpointWitnessScope{
			DeviceID: stringField(ackScope, "device_id"),
			AccountID: stringField(ackScope, "account_id"),
			OrganizationID: stringField(ackScope, "organization_id"),
		},
		JTI: stringField(ackVector, "jti"),
		Decision: stringField(ackVector, "decision"),
		WitnessKeyID: stringField(ackVector, "witness_key_id"),
	}
	copy(ack.RequestSHA256[:], decode(stringField(ackVector, "request_sha256")))
	copy(ack.PrimaryReceiptSHA256[:], decode(stringField(ackVector, "primary_receipt_sha256")))
	if hexBytes(checkpointWitnessAckMessage(ack)) != stringField(ackVector, "message_hex") {
		t.Fatal("witness acknowledgement encoding differs from shared vector")
	}

	witnessHeadVector := object(vector["witness_head"])
	witnessHeadScope := object(witnessHeadVector["scope"])
	witnessHead := CheckpointWitnessHead{
		WitnessID: stringField(witnessHeadVector, "witness_id"),
		Scope: CheckpointWitnessScope{
			DeviceID: stringField(witnessHeadScope, "device_id"),
			AccountID: stringField(witnessHeadScope, "account_id"),
			OrganizationID: stringField(witnessHeadScope, "organization_id"),
		},
		Generation: uintField(witnessHeadVector, "generation"),
		PrimaryGeneration: uintField(witnessHeadVector, "primary_generation"),
		RevocationEpoch: uintField(witnessHeadVector, "revocation_epoch"),
		WitnessKeyID: stringField(witnessHeadVector, "witness_key_id"),
	}
	copy(witnessHead.RecordHash[:], decode(stringField(witnessHeadVector, "record_hash")))
	copy(witnessHead.PrimaryHead[:], decode(stringField(witnessHeadVector, "primary_head")))
	if hexBytes(checkpointWitnessHeadMessage(witnessHead)) != stringField(witnessHeadVector, "message_hex") {
		t.Fatal("witness head encoding differs from shared vector")
	}

	canonicalVector := object(vector["canonical_payload"])
	canonical, err := json.Marshal(object(canonicalVector["value"]))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != stringField(canonicalVector, "canonical_json") {
		t.Fatalf("canonical JSON=%s", canonical)
	}
	canonicalDigest := sha256.Sum256(canonical)
	if hexBytes(canonicalDigest[:]) != stringField(canonicalVector, "sha256") {
		t.Fatal("canonical payload digest differs from shared vector")
	}
}

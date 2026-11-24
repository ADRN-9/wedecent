package portforward

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCheckpointEventV2SharedSQLGoVector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/portforward/checkpoint_event_v2_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Action            string `json:"action"`
		ScopeKind         string `json:"scope_kind"`
		DeviceID          string `json:"device_id"`
		AccountID         string `json:"account_id"`
		OrganizationID    string `json:"organization_id"`
		OperationID       string `json:"operation_id"`
		RequestSHA256     string `json:"request_sha256"`
		ParticipantSHA256 string `json:"participant_sha256"`
		PreviousHash      string `json:"previous_hash"`
		Generation        uint64 `json:"generation"`
		RevocationEpoch   uint64 `json:"revocation_epoch"`
		EncodingHex       string `json:"encoding_hex"`
		EventSHA256       string `json:"event_sha256"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	decode32 := func(value string) [32]byte {
		t.Helper()
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("invalid 32-byte vector value: %v", err)
		}
		var result [32]byte
		copy(result[:], decoded)
		return result
	}
	event := CheckpointEventV2{
		Action: CheckpointFenceAction(vector.Action),
		Scope: CheckpointWitnessScope{
			Kind: vector.ScopeKind, DeviceID: vector.DeviceID,
			AccountID: vector.AccountID, OrganizationID: vector.OrganizationID,
		},
		OperationID:       vector.OperationID,
		RequestSHA256:     decode32(vector.RequestSHA256),
		ParticipantSHA256: decode32(vector.ParticipantSHA256),
		PreviousHash:      decode32(vector.PreviousHash),
		Generation:        vector.Generation,
		RevocationEpoch:   vector.RevocationEpoch,
	}
	encoding, err := CheckpointEventV2Encoding(event)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encoding); got != vector.EncodingHex {
		t.Fatalf("canonical event encoding mismatch\n got: %s\nwant: %s", got, vector.EncodingHex)
	}
	hash, err := CheckpointEventV2Hash(event)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(hash[:]); got != vector.EventSHA256 {
		t.Fatalf("canonical event hash mismatch: got %s want %s", got, vector.EventSHA256)
	}
}

func TestCheckpointEventV2RejectsInvalidFields(t *testing.T) {
	event := CheckpointEventV2{
		Action: CheckpointFenceFinalize,
		Scope: CheckpointWitnessScope{
			Kind: "device", DeviceID: "wd_aaaaaaaaaaaaaaaa",
			AccountID: "11111111-1111-4111-8111-111111111111",
			OrganizationID: "22222222-2222-4222-8222-222222222222",
		},
		OperationID:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		RequestSHA256:     [32]byte{1},
		ParticipantSHA256: [32]byte{2},
		Generation:        1,
	}
	if _, err := CheckpointEventV2Encoding(event); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	event.Generation = 1 << 63
	if _, err := CheckpointEventV2Encoding(event); err == nil {
		t.Fatal("generation outside PostgreSQL bigint range was accepted")
	}
}

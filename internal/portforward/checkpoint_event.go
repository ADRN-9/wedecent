package portforward

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

const checkpointEventV2Domain = "wedecent-checkpoint-event-v2"

type CheckpointEventV2 struct {
	Action            CheckpointFenceAction
	Scope             CheckpointWitnessScope
	OperationID       string
	RequestSHA256     [sha256.Size]byte
	ParticipantSHA256 [sha256.Size]byte
	PreviousHash      [sha256.Size]byte
	Generation        uint64
	RevocationEpoch   uint64
}

// CheckpointEventV2Encoding is the versioned SQL/Go canonical event preimage.
// It intentionally differs from historical replay-entry hashing; callers must
// preserve old hashes as anchors rather than recomputing them.
func CheckpointEventV2Encoding(event CheckpointEventV2) ([]byte, error) {
	if (event.Action != CheckpointFenceFinalize && event.Action != CheckpointFenceRevoke) ||
		!validCheckpointFenceScope(event.Scope) ||
		(event.Scope.Kind != "device" && event.Scope.Kind != "organization") ||
		len(event.OperationID) != 64 || event.OperationID != stringLowerHex(event.OperationID) ||
		event.RequestSHA256 == ([sha256.Size]byte{}) ||
		event.ParticipantSHA256 == ([sha256.Size]byte{}) ||
		event.Generation == 0 || event.Generation > (1<<63)-1 ||
		event.RevocationEpoch > (1<<63)-1 {
		return nil, ErrCheckpointIntegrity
	}
	var b bytes.Buffer
	b.WriteString(checkpointEventV2Domain)
	b.WriteByte(0)
	putString := func(value string) error {
		if uint64(len(value)) > (1<<32)-1 {
			return ErrCheckpointIntegrity
		}
		if err := binary.Write(&b, binary.BigEndian, uint32(len(value))); err != nil {
			return err
		}
		_, err := b.WriteString(value)
		return err
	}
	for _, value := range []string{
		string(event.Action), event.Scope.Kind, event.Scope.DeviceID,
		event.Scope.AccountID, event.Scope.OrganizationID, event.OperationID,
	} {
		if err := putString(value); err != nil {
			return nil, err
		}
	}
	b.Write(event.RequestSHA256[:])
	b.Write(event.ParticipantSHA256[:])
	b.Write(event.PreviousHash[:])
	if err := binary.Write(&b, binary.BigEndian, event.Generation); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, event.RevocationEpoch); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func CheckpointEventV2Hash(event CheckpointEventV2) ([sha256.Size]byte, error) {
	encoding, err := CheckpointEventV2Encoding(event)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoding), nil
}

func stringLowerHex(value string) string {
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	for _, c := range value {
		if c >= 'A' && c <= 'F' {
			return ""
		}
	}
	return value
}

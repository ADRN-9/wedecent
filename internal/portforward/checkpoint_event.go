package portforward

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

const checkpointEventV2Domain = "wedecent-checkpoint-event-v2"

type CheckpointEventV2 struct {
	Action          CheckpointFenceAction
	Scope           CheckpointWitnessScope
	OperationID     string
	RequestSHA256   [sha256.Size]byte
	Participants    []CheckpointParticipant
	PreviousHash    [sha256.Size]byte
	Generation      uint64
	RevocationEpoch uint64
}

// The digest is derived internally from validated participant records.
func CheckpointEventV2Encoding(event CheckpointEventV2) ([]byte, error) {
	if (event.Action != CheckpointFenceFinalize && event.Action != CheckpointFenceRevoke) ||
		!validCheckpointFenceScope(event.Scope) ||
		(event.Scope.Kind != "device" && event.Scope.Kind != "organization") ||
		len(event.OperationID) != 64 || event.OperationID != stringLowerHex(event.OperationID) ||
		event.RequestSHA256 == ([32]byte{}) || event.Generation == 0 ||
		event.Generation > (1<<63)-1 || event.RevocationEpoch > (1<<63)-1 {
		return nil, ErrCheckpointIntegrity
	}
	ps, err := CanonicalCheckpointParticipants(event.Participants)
	if err != nil {
		return nil, err
	}
	if event.Scope.Kind == "device" {
		found := false
		for _, p := range ps {
			if p.DeviceID == event.Scope.DeviceID && p.AccountID == event.Scope.AccountID &&
				p.OrganizationID == event.Scope.OrganizationID && p.RevocationEpoch == event.RevocationEpoch {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrCheckpointIntegrity
		}
	}
	for _, p := range ps {
		if p.OrganizationID != event.Scope.OrganizationID {
			return nil, ErrCheckpointIntegrity
		}
	}
	digest, err := CheckpointParticipantVectorDigest(ps)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(checkpointEventV2Domain)
	b.WriteByte(0)
	for _, s := range []string{
		string(event.Action), event.Scope.Kind, event.Scope.DeviceID,
		event.Scope.AccountID, event.Scope.OrganizationID, event.OperationID,
	} {
		if err := writeCheckpointV2String(&b, s); err != nil {
			return nil, err
		}
	}
	b.Write(event.RequestSHA256[:])
	b.Write(digest[:])
	b.Write(event.PreviousHash[:])
	if err := binary.Write(&b, binary.BigEndian, event.Generation); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, event.RevocationEpoch); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func CheckpointEventV2Hash(event CheckpointEventV2) ([32]byte, error) {
	enc, err := CheckpointEventV2Encoding(event)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(enc), nil
}

func stringLowerHex(s string) string {
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	for _, c := range s {
		if c >= 'A' && c <= 'F' {
			return ""
		}
	}
	return s
}

package portforward

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
)

const checkpointParticipantVectorV1Domain = "wedecent-checkpoint-participant-vector-v1"

type CheckpointParticipant struct {
	DeviceID        string
	AccountID       string
	OrganizationID  string
	RevocationEpoch uint64
	HeadGeneration  uint64
	HeadHash        [sha256.Size]byte
}

type CheckpointV1Head struct {
	DeviceID        string
	AccountID       string
	OrganizationID  string
	RevocationEpoch uint64
	Generation      uint64
	StateHash       [sha256.Size]byte
}

func (h CheckpointV1Head) NextGeneration() (uint64, error) {
	if h.Generation >= (1<<63)-1 {
		return 0, ErrCheckpointStale
	}
	return h.Generation + 1, nil
}

func CanonicalCheckpointParticipants(input []CheckpointParticipant) ([]CheckpointParticipant, error) {
	if len(input) == 0 || uint64(len(input)) > uint64(^uint32(0)) {
		return nil, ErrCheckpointIntegrity
	}
	out := append([]CheckpointParticipant(nil), input...)
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	org := out[0].OrganizationID
	for i, p := range out {
		ep := CheckpointEndpoint{
			DeviceID: p.DeviceID, AccountID: p.AccountID,
			OrganizationID: p.OrganizationID, RevocationEpoch: p.RevocationEpoch,
		}
		if !validCheckpointEndpoint(ep) || p.OrganizationID != org ||
			p.RevocationEpoch > (1<<63)-1 || p.HeadGeneration > (1<<63)-1 ||
			(i > 0 && out[i-1].DeviceID == p.DeviceID) ||
			(p.HeadGeneration == 0 && p.HeadHash != ([32]byte{})) ||
			(p.HeadGeneration > 0 && p.HeadHash == ([32]byte{})) {
			return nil, ErrCheckpointIntegrity
		}
	}
	return out, nil
}

func CheckpointParticipantVectorEncoding(input []CheckpointParticipant) ([]byte, error) {
	ps, err := CanonicalCheckpointParticipants(input)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(checkpointParticipantVectorV1Domain)
	b.WriteByte(0)
	if err := binary.Write(&b, binary.BigEndian, uint32(len(ps))); err != nil {
		return nil, err
	}
	for _, p := range ps {
		for _, s := range []string{p.DeviceID, p.AccountID, p.OrganizationID} {
			if err := writeCheckpointV2String(&b, s); err != nil {
				return nil, err
			}
		}
		for _, n := range []uint64{p.RevocationEpoch, p.HeadGeneration} {
			if err := binary.Write(&b, binary.BigEndian, n); err != nil {
				return nil, err
			}
		}
		b.Write(p.HeadHash[:])
	}
	return b.Bytes(), nil
}

func CheckpointParticipantVectorDigest(input []CheckpointParticipant) ([32]byte, error) {
	enc, err := CheckpointParticipantVectorEncoding(input)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(enc), nil
}

// The caller must still compare these values under database row locks before a v2 write.
func ValidateCheckpointV1ToV2Transition(claimed []CheckpointParticipant, authoritative []CheckpointV1Head) ([32]byte, error) {
	ps, err := CanonicalCheckpointParticipants(claimed)
	if err != nil || len(ps) != len(authoritative) {
		return [32]byte{}, ErrCheckpointStale
	}
	heads := append([]CheckpointV1Head(nil), authoritative...)
	sort.Slice(heads, func(i, j int) bool { return heads[i].DeviceID < heads[j].DeviceID })
	for i, p := range ps {
		h := heads[i]
		if h.DeviceID != p.DeviceID || h.AccountID != p.AccountID || h.OrganizationID != p.OrganizationID ||
			h.RevocationEpoch != p.RevocationEpoch || h.Generation != p.HeadGeneration || h.StateHash != p.HeadHash {
			return [32]byte{}, ErrCheckpointStale
		}
		if _, err := h.NextGeneration(); err != nil {
			return [32]byte{}, err
		}
		if (h.Generation == 0 && h.StateHash != ([32]byte{})) ||
			(h.Generation > 0 && h.StateHash == ([32]byte{})) {
			return [32]byte{}, ErrCheckpointStale
		}
		if i > 0 && heads[i-1].DeviceID == h.DeviceID {
			return [32]byte{}, ErrCheckpointIntegrity
		}
	}
	return CheckpointParticipantVectorDigest(ps)
}

func writeCheckpointV2String(b *bytes.Buffer, s string) error {
	if uint64(len(s)) > uint64(^uint32(0)) {
		return ErrCheckpointIntegrity
	}
	if err := binary.Write(b, binary.BigEndian, uint32(len(s))); err != nil {
		return err
	}
	_, err := b.WriteString(s)
	return err
}

func decodeCheckpointSHA256(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, ErrCheckpointIntegrity
	}
	copy(out[:], raw)
	return out, nil
}

package portforward

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func c187P() CheckpointParticipant {
	var h [32]byte
	for i := range h {
		h[i] = 0x33
	}
	return CheckpointParticipant{
		DeviceID: "wd_aaaaaaaaaaaaaaaa", AccountID: "11111111-1111-4111-8111-111111111111",
		OrganizationID: "22222222-2222-4222-8222-222222222222", RevocationEpoch: 7,
		HeadGeneration: 41, HeadHash: h,
	}
}

func c187E() CheckpointEventV2 {
	var r, p [32]byte
	for i := range r {
		r[i] = 0x11
		p[i] = 0x33
	}
	x := c187P()
	return CheckpointEventV2{
		Action: CheckpointFenceFinalize,
		Scope: CheckpointWitnessScope{
			Kind: "device", DeviceID: x.DeviceID, AccountID: x.AccountID,
			OrganizationID: x.OrganizationID,
		},
		OperationID:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		RequestSHA256: r, Participants: []CheckpointParticipant{x},
		PreviousHash: p, Generation: 42, RevocationEpoch: 7,
	}
}

func TestC187ParticipantOrderingAndBindings(t *testing.T) {
	a := c187P()
	b := a
	b.DeviceID = "wd_bbbbbbbbbbbbbbbb"
	b.AccountID = "33333333-3333-4333-8333-333333333333"
	b.HeadGeneration = 9
	b.HeadHash[0] = 0x44
	d, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{a, b})
	if err != nil {
		t.Fatal(err)
	}
	r, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{b, a})
	if err != nil || r != d {
		t.Fatal("ordering changed digest")
	}
	mutations := []func(*CheckpointParticipant){
		func(p *CheckpointParticipant) { p.DeviceID = "wd_cccccccccccccccc" },
		func(p *CheckpointParticipant) { p.AccountID = "44444444-4444-4444-8444-444444444444" },
		func(p *CheckpointParticipant) { p.RevocationEpoch++ },
		func(p *CheckpointParticipant) { p.HeadGeneration++ },
		func(p *CheckpointParticipant) { p.HeadHash[0]++ },
	}
	for i, mutate := range mutations {
		changed := b
		mutate(&changed)
		got, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{a, changed})
		if err != nil || got == d {
			t.Fatalf("mutation %d not bound", i)
		}
	}
	b.OrganizationID = "55555555-5555-4555-8555-555555555555"
	if _, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{a, b}); err == nil {
		t.Fatal("mixed organizations accepted")
	}
	organizationChanged := a
	organizationChanged.OrganizationID = "55555555-5555-4555-8555-555555555555"
	orgDigest, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{organizationChanged})
	if err != nil || orgDigest == mustC187ParticipantDigest(t, a) {
		t.Fatal("organization substitution not bound")
	}
}

func mustC187ParticipantDigest(t *testing.T, p CheckpointParticipant) [32]byte {
	t.Helper()
	digest, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{p})
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestC187RejectsEmptyDuplicateMalformedAndOverflow(t *testing.T) {
	p := c187P()
	if _, err := CheckpointParticipantVectorDigest(nil); err == nil {
		t.Fatal("empty vector accepted")
	}
	if _, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{p, p}); err == nil {
		t.Fatal("duplicate accepted")
	}
	p.DeviceID = ""
	if _, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{p}); err == nil {
		t.Fatal("missing device accepted")
	}
	p = c187P()
	p.AccountID = ""
	if _, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{p}); err == nil {
		t.Fatal("missing account accepted")
	}
	p = c187P()
	p.HeadHash = [32]byte{}
	if _, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{p}); err == nil {
		t.Fatal("bad head accepted")
	}
	p = c187P()
	p.RevocationEpoch = 1 << 63
	if _, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{p}); err == nil {
		t.Fatal("epoch overflow accepted")
	}
	p = c187P()
	p.HeadGeneration = 1 << 63
	if _, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{p}); err == nil {
		t.Fatal("generation overflow accepted")
	}
}

func TestC187HistoricalV1Transition(t *testing.T) {
	p := c187P()
	heads := []CheckpointV1Head{{
		DeviceID: p.DeviceID, AccountID: p.AccountID, OrganizationID: p.OrganizationID,
		RevocationEpoch: p.RevocationEpoch, Generation: p.HeadGeneration, StateHash: p.HeadHash,
	}}
	digest, err := ValidateCheckpointV1ToV2Transition([]CheckpointParticipant{p}, heads)
	if err != nil {
		t.Fatal(err)
	}
	want, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{p})
	if err != nil || digest != want {
		t.Fatal("v1 anchor digest mismatch")
	}
	stale := append([]CheckpointV1Head(nil), heads...)
	stale[0].Generation--
	if _, err := ValidateCheckpointV1ToV2Transition([]CheckpointParticipant{p}, stale); err == nil {
		t.Fatal("stale head accepted")
	}
	substituted := append([]CheckpointV1Head(nil), heads...)
	substituted[0].StateHash[0] ^= 0xff
	if _, err := ValidateCheckpointV1ToV2Transition([]CheckpointParticipant{p}, substituted); err == nil {
		t.Fatal("substituted hash accepted")
	}
	if _, err := ValidateCheckpointV1ToV2Transition([]CheckpointParticipant{p}, nil); err == nil {
		t.Fatal("missing head accepted")
	}
}

func TestC187SharedVectorAndSQLConsistency(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/portforward/checkpoint_event_v2_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Encoding    string `json:"encoding_hex"`
		Hash        string `json:"event_sha256"`
		Participant string `json:"participant_sha256"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	encoding, err := CheckpointEventV2Encoding(c187E())
	if err != nil || hex.EncodeToString(encoding) != vector.Encoding {
		t.Fatal("event vector mismatch")
	}
	hash, err := CheckpointEventV2Hash(c187E())
	if err != nil || hex.EncodeToString(hash[:]) != vector.Hash {
		t.Fatal("event hash mismatch")
	}
	digest, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{c187P()})
	if err != nil || hex.EncodeToString(digest[:]) != vector.Participant {
		t.Fatal("participant digest mismatch")
	}
	sql, err := os.ReadFile("../../supabase/tests/database/checkpoint_participant_binding.test.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{vector.Encoding, vector.Hash, vector.Participant} {
		if !bytes.Contains(sql, []byte(value)) {
			t.Fatal("SQL fixture differs from Go vector")
		}
	}
}

func TestC187UTF8AndMalformedDigest(t *testing.T) {
	var b bytes.Buffer
	if err := writeCheckpointV2String(&b, "café"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Bytes(), []byte{0, 0, 0, 5, 'c', 'a', 'f', 0xc3, 0xa9}) {
		t.Fatalf("wrong UTF8 length %x", b.Bytes())
	}
	if _, err := decodeCheckpointSHA256(strings.Repeat("ab", 31)); err == nil {
		t.Fatal("short digest accepted")
	}
	if _, err := decodeCheckpointSHA256(strings.Repeat("zz", 32)); err == nil {
		t.Fatal("bad hex accepted")
	}
}

func TestC187EventScopeAndOverflow(t *testing.T) {
	event := c187E()
	event.Participants = nil
	if _, err := CheckpointEventV2Encoding(event); err == nil {
		t.Fatal("missing participants accepted")
	}
	event = c187E()
	event.Participants[0].AccountID = "33333333-3333-4333-8333-333333333333"
	if _, err := CheckpointEventV2Encoding(event); err == nil {
		t.Fatal("scope substitution accepted")
	}
	event = c187E()
	event.Participants[0].RevocationEpoch++
	if _, err := CheckpointEventV2Encoding(event); err == nil {
		t.Fatal("scoped epoch mismatch accepted")
	}
	event = c187E()
	event.Generation = 1 << 63
	if _, err := CheckpointEventV2Encoding(event); err == nil {
		t.Fatal("generation overflow accepted")
	}
	event = c187E()
	event.RevocationEpoch = 1 << 63
	if _, err := CheckpointEventV2Encoding(event); err == nil {
		t.Fatal("epoch overflow accepted")
	}
}

func TestC187ParticipantOrderingAndHistoricalGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/portforward/checkpoint_participant_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Ordering struct {
			Unordered []struct {
				DeviceID        string `json:"device_id"`
				AccountID       string `json:"account_id"`
				OrganizationID  string `json:"organization_id"`
				RevocationEpoch uint64 `json:"revocation_epoch"`
				HeadGeneration  uint64 `json:"head_generation"`
				HeadHash        string `json:"head_hash"`
			} `json:"unordered"`
			Encoding string `json:"encoding_hex"`
			Digest   string `json:"digest_sha256"`
		} `json:"participant_ordering"`
		Historical struct {
			Participant struct {
				DeviceID        string `json:"device_id"`
				AccountID       string `json:"account_id"`
				OrganizationID  string `json:"organization_id"`
				RevocationEpoch uint64 `json:"revocation_epoch"`
				HeadGeneration  uint64 `json:"head_generation"`
				HeadHash        string `json:"head_hash"`
			} `json:"participant"`
			Head struct {
				DeviceID        string `json:"device_id"`
				AccountID       string `json:"account_id"`
				OrganizationID  string `json:"organization_id"`
				RevocationEpoch uint64 `json:"revocation_epoch"`
				Generation      uint64 `json:"generation"`
				StateHash       string `json:"state_hash"`
			} `json:"authoritative_v1_head"`
			Digest         string `json:"participant_vector_digest"`
			NextGeneration uint64 `json:"next_generation"`
		} `json:"historical_v1_to_v2"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	participants := make([]CheckpointParticipant, 0, len(vector.Ordering.Unordered))
	for _, p := range vector.Ordering.Unordered {
		headHash, err := decodeCheckpointSHA256(p.HeadHash)
		if err != nil {
			t.Fatal(err)
		}
		participants = append(participants, CheckpointParticipant{
			DeviceID: p.DeviceID, AccountID: p.AccountID, OrganizationID: p.OrganizationID,
			RevocationEpoch: p.RevocationEpoch, HeadGeneration: p.HeadGeneration, HeadHash: headHash,
		})
	}
	encoding, err := CheckpointParticipantVectorEncoding(participants)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encoding) != vector.Ordering.Encoding {
		t.Fatal("participant ordering encoding vector mismatch")
	}
	digest, err := CheckpointParticipantVectorDigest(participants)
	if err != nil || hex.EncodeToString(digest[:]) != vector.Ordering.Digest {
		t.Fatal("participant ordering digest vector mismatch")
	}
	p := vector.Historical.Participant
	headHash, err := decodeCheckpointSHA256(p.HeadHash)
	if err != nil {
		t.Fatal(err)
	}
	participant := CheckpointParticipant{
		DeviceID: p.DeviceID, AccountID: p.AccountID, OrganizationID: p.OrganizationID,
		RevocationEpoch: p.RevocationEpoch, HeadGeneration: p.HeadGeneration, HeadHash: headHash,
	}
	h := vector.Historical.Head
	stateHash, err := decodeCheckpointSHA256(h.StateHash)
	if err != nil {
		t.Fatal(err)
	}
	actual := CheckpointV1Head{
		DeviceID: h.DeviceID, AccountID: h.AccountID, OrganizationID: h.OrganizationID,
		RevocationEpoch: h.RevocationEpoch, Generation: h.Generation, StateHash: stateHash,
	}
	transitionDigest, err := ValidateCheckpointV1ToV2Transition([]CheckpointParticipant{participant}, []CheckpointV1Head{actual})
	if err != nil || hex.EncodeToString(transitionDigest[:]) != vector.Historical.Digest {
		t.Fatal("historical transition vector mismatch")
	}
	next, err := actual.NextGeneration()
	if err != nil || next != vector.Historical.NextGeneration {
		t.Fatal("historical generation was reset or skipped")
	}
	sql, err := os.ReadFile("../../supabase/tests/database/checkpoint_participant_binding.test.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sql, []byte(vector.Ordering.Digest)) {
		t.Fatal("SQL participant ordering vector missing")
	}
}

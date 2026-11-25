package portforward

import "testing"

func TestCheckpointV1NextGenerationIsMonotonicAndBounded(t *testing.T) {
	genesis := CheckpointV1Head{}
	next, err := genesis.NextGeneration()
	if err != nil || next != 1 {
		t.Fatalf("genesis must advance to one: next=%d err=%v", next, err)
	}
	current := CheckpointV1Head{Generation: (1 << 63) - 2}
	next, err = current.NextGeneration()
	if err != nil || next != (1<<63)-1 {
		t.Fatalf("maximum PostgreSQL generation boundary: next=%d err=%v", next, err)
	}
	current.Generation = (1 << 63) - 1
	if _, err := current.NextGeneration(); err == nil {
		t.Fatal("generation overflow accepted")
	}
}

func TestCheckpointParticipantBigintMaximumAccepted(t *testing.T) {
	p := c187P()
	p.RevocationEpoch = (1 << 63) - 1
	p.HeadGeneration = (1 << 63) - 1
	if _, err := CheckpointParticipantVectorDigest([]CheckpointParticipant{p}); err != nil {
		t.Fatalf("signed bigint maximum rejected: %v", err)
	}
}

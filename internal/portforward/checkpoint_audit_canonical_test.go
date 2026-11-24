package portforward

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCheckpointAuditSharedCanonicalVectors(t *testing.T) {
	data, err := os.ReadFile("../../supabase/tests/fixtures/checkpoint-audit-canonical-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Name      string          `json:"name"`
			Input     json.RawMessage `json:"input"`
			Canonical string          `json:"canonical"`
			SHA256    string          `json:"sha256"`
		} `json:"vectors"`
		Invalid []struct {
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(vector.Input))
			decoder.UseNumber()
			var value any
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			canonical, err := checkpointAuditCanonicalJSON(value)
			if err != nil {
				t.Fatal(err)
			}
			if string(canonical) != vector.Canonical {
				t.Fatalf("canonical mismatch:\n got %s\nwant %s", canonical, vector.Canonical)
			}
			digest := sha256.Sum256(canonical)
			if hex.EncodeToString(digest[:]) != vector.SHA256 {
				t.Fatalf("digest mismatch: got %x want %s", digest, vector.SHA256)
			}
		})
	}
	for _, vector := range fixture.Invalid {
		t.Run("reject-"+vector.Name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(vector.Input))
			decoder.UseNumber()
			var value any
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			if _, err := checkpointAuditCanonicalJSON(value); err == nil {
				t.Fatal("unsafe canonical number accepted")
			}
		})
	}
}

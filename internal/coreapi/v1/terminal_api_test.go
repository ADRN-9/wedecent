package v1

import (
	"encoding/json"
	"testing"
)

func TestTerminalWireMethodNames(t *testing.T) {
	methods := map[string]string{
		MethodTerminalRead:   "terminal.read",
		MethodTerminalWrite:  "terminal.write",
		MethodTerminalResize: "terminal.resize",
	}
	for got, want := range methods {
		if got != want {
			t.Fatalf("terminal method = %q, want %q", got, want)
		}
	}
	if MaxTerminalChunkBytes != 32<<10 {
		t.Fatalf("MaxTerminalChunkBytes = %d", MaxTerminalChunkBytes)
	}
}

func TestTerminalReadResultUsesJSONBase64ForBytes(t *testing.T) {
	data, err := json.Marshal(TerminalReadResult{Data: []byte{0, 1, 2, 255}, Closed: true})
	if err != nil {
		t.Fatal(err)
	}
	var got TerminalReadResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Data) != 4 || got.Data[3] != 255 || !got.Closed {
		t.Fatalf("round trip = %#v", got)
	}
}

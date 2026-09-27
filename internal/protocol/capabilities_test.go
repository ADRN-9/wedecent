package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSessionCapabilityEncodingPreservesLegacyDefault(t *testing.T) {
	got, err := JSON(OpenSession{Cols: 80, Rows: 24, Term: "xterm"})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"cols":80,"rows":24,"term":"xterm"}`
	if string(got) != want {
		t.Fatalf("default OpenSession JSON = %s, want %s", got, want)
	}

	authorized, err := JSON(OpenAuthorizedSession{
		Cols:            80,
		Rows:            24,
		Term:            "xterm",
		ConnectionGrant: "header.payload.signature",
	})
	if err != nil {
		t.Fatal(err)
	}
	const wantAuthorized = `{"cols":80,"rows":24,"term":"xterm","connection_grant":"header.payload.signature"}`
	if string(authorized) != wantAuthorized {
		t.Fatalf("default OpenAuthorizedSession JSON = %s, want %s", authorized, wantAuthorized)
	}
}

func TestTypedStreamCapabilityIsOptionalAndExplicit(t *testing.T) {
	payload, err := JSON(OpenSession{
		Cols:         100,
		Rows:         40,
		Term:         "xterm-256color",
		Capabilities: []Capability{CapabilityTypedStreamsV1},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded OpenSession
	if err := ParseJSON(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Capabilities, []Capability{CapabilityTypedStreamsV1}) {
		t.Fatalf("capabilities = %#v", decoded.Capabilities)
	}
	if !SupportedCapability(decoded.Capabilities[0]) || SupportedCapability("renderer-invented") {
		t.Fatal("capability support classification is not fail-closed")
	}
}

func TestLegacyPeerCanIgnoreRequestedCapabilities(t *testing.T) {
	type legacyOpenSession struct {
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
		Term string `json:"term"`
	}
	payload, err := JSON(OpenSession{
		Cols:         80,
		Rows:         24,
		Term:         "xterm",
		Capabilities: []Capability{CapabilityTypedStreamsV1},
	})
	if err != nil {
		t.Fatal(err)
	}
	var legacy legacyOpenSession
	if err := json.Unmarshal(payload, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Cols != 80 || legacy.Rows != 24 || legacy.Term != "xterm" {
		t.Fatalf("legacy decoded request = %#v", legacy)
	}

	var accepted SessionAccepted
	if err := ParseJSON(nil, &accepted); err == nil {
		t.Fatal("empty payload unexpectedly parsed as negotiated capabilities")
	}
	if len(accepted.Capabilities) != 0 {
		t.Fatalf("empty legacy acceptance negotiated capabilities: %#v", accepted.Capabilities)
	}
}

package session

import (
	"reflect"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestNegotiateSessionCapabilitiesRequiresReadyRuntime(t *testing.T) {
	requested := []protocol.Capability{protocol.CapabilityTypedStreamsV1}
	if got := negotiateSessionCapabilities(requested, false); len(got) != 0 {
		t.Fatalf("negotiated before runtime ready: %#v", got)
	}
	want := []protocol.Capability{protocol.CapabilityTypedStreamsV1}
	if got := negotiateSessionCapabilities(requested, true); !reflect.DeepEqual(got, want) {
		t.Fatalf("negotiated = %#v, want %#v", got, want)
	}
}

func TestNegotiateSessionCapabilitiesIgnoresUnknownAndDeduplicates(t *testing.T) {
	requested := []protocol.Capability{
		"renderer-invented",
		protocol.CapabilityTypedStreamsV1,
		protocol.CapabilityTypedStreamsV1,
		"future-unknown",
	}
	want := []protocol.Capability{protocol.CapabilityTypedStreamsV1}
	got := negotiateSessionCapabilities(requested, true)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("negotiated = %#v, want %#v", got, want)
	}
	if hasSessionCapability(got, "renderer-invented") || !hasSessionCapability(got, protocol.CapabilityTypedStreamsV1) {
		t.Fatalf("capability membership incorrect: %#v", got)
	}
}

func TestNegotiateSessionCapabilitiesDoesNotInventSupport(t *testing.T) {
	got := negotiateSessionCapabilities([]protocol.Capability{"future-unknown"}, true)
	if len(got) != 0 {
		t.Fatalf("unknown capability accepted: %#v", got)
	}
}

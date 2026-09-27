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

func TestNegotiateFileTransferRequiresTypedAndReadyFileRuntime(t *testing.T) {
	both := []protocol.Capability{
		protocol.CapabilityTypedStreamsV1,
		protocol.CapabilityFileTransferV1,
	}
	wantBoth := []protocol.Capability{
		protocol.CapabilityTypedStreamsV1,
		protocol.CapabilityFileTransferV1,
	}
	if got := negotiateSessionCapabilitiesForRuntime(both, true, true); !reflect.DeepEqual(got, wantBoth) {
		t.Fatalf("ready negotiation = %#v, want %#v", got, wantBoth)
	}
	if got := negotiateSessionCapabilitiesForRuntime(both, true, false); !reflect.DeepEqual(got, []protocol.Capability{protocol.CapabilityTypedStreamsV1}) {
		t.Fatalf("file capability negotiated without file runtime: %#v", got)
	}
	if got := negotiateSessionCapabilitiesForRuntime([]protocol.Capability{protocol.CapabilityFileTransferV1}, true, true); len(got) != 0 {
		t.Fatalf("file capability negotiated without typed framing: %#v", got)
	}
	if got := negotiateSessionCapabilitiesForRuntime(both, false, true); len(got) != 0 {
		t.Fatalf("file capability negotiated without typed runtime: %#v", got)
	}
}

func TestLegacyNegotiationWrapperNeverAdvertisesFileTransfer(t *testing.T) {
	requested := []protocol.Capability{
		protocol.CapabilityTypedStreamsV1,
		protocol.CapabilityFileTransferV1,
	}
	got := negotiateSessionCapabilities(requested, true)
	want := []protocol.Capability{protocol.CapabilityTypedStreamsV1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy live negotiation = %#v, want %#v", got, want)
	}
}

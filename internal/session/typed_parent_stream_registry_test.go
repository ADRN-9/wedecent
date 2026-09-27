package session

import (
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestTypedParentRegistryPreventsCrossKindReuse(t *testing.T) {
	registry := newTypedParentStreamRegistry()
	terminals := newTypedTerminalStreamSetWithRegistry(registry)
	if err := terminals.reserve(2); err != nil {
		t.Fatal(err)
	}
	if err := terminals.accept(2); err != nil {
		t.Fatal(err)
	}
	if err := registry.reserve(2, protocol.StreamKindFileUpload); !errors.Is(err, errTypedStreamDuplicate) {
		t.Fatalf("cross-kind duplicate error = %v", err)
	}
	if err := terminals.close(2); err != nil {
		t.Fatal(err)
	}
	if err := registry.reserve(2, protocol.StreamKindFileDownload); !errors.Is(err, errTypedStreamDuplicate) {
		t.Fatalf("closed cross-kind reuse error = %v", err)
	}
}

func TestTypedParentRegistryLifetimeLimitIsAggregateAcrossKinds(t *testing.T) {
	registry := newTypedParentStreamRegistry()
	for i := 0; i < maxTypedStreamIDsPerConnection; i++ {
		id := protocol.MinTypedStreamID + uint32(i)
		kind := protocol.StreamKindTerminal
		if i%2 == 1 {
			kind = protocol.StreamKindFileUpload
		}
		if err := registry.reserve(id, kind); err != nil {
			t.Fatalf("reserve %d: %v", id, err)
		}
		if err := registry.accept(id, kind); err != nil {
			t.Fatalf("accept %d: %v", id, err)
		}
		if err := registry.close(id, kind); err != nil {
			t.Fatalf("close %d: %v", id, err)
		}
	}
	if err := registry.reserve(protocol.MinTypedStreamID+maxTypedStreamIDsPerConnection, protocol.StreamKindFileDownload); !errors.Is(err, errTypedStreamLimit) {
		t.Fatalf("aggregate lifetime limit error = %v", err)
	}
}

func TestTypedTerminalSharedRegistryKeepsTerminalLimitAndFileStateIndependent(t *testing.T) {
	registry := newTypedParentStreamRegistry()
	terminals := newTypedTerminalStreamSetWithRegistry(registry)
	if err := registry.reserve(100, protocol.StreamKindFileUpload); err != nil {
		t.Fatal(err)
	}
	if err := registry.accept(100, protocol.StreamKindFileUpload); err != nil {
		t.Fatal(err)
	}

	for id := protocol.MinTypedStreamID; id <= maxTerminalStreamsPerConnection; id++ {
		if err := terminals.reserve(id); err != nil {
			t.Fatalf("reserve terminal %d: %v", id, err)
		}
		if err := terminals.accept(id); err != nil {
			t.Fatalf("accept terminal %d: %v", id, err)
		}
	}
	if err := terminals.reserve(maxTerminalStreamsPerConnection + 1); !errors.Is(err, errTypedStreamLimit) {
		t.Fatalf("terminal concurrency limit error = %v", err)
	}
	terminals.closeAll()
	if !registry.isOpen(100, protocol.StreamKindFileUpload) {
		t.Fatal("terminal closeAll closed sibling file stream")
	}
}

func TestTypedTerminalServerCanBindSharedRegistry(t *testing.T) {
	registry := newTypedParentStreamRegistry()
	server := newTypedTerminalServerWithStarterAndRegistry(
		"/bin/sh",
		func(protocol.Frame) error { return nil },
		func(string, uint16, uint16, string) (typedTerminalPTY, error) { return newFakeTypedPTY(), nil },
		registry,
	)
	if server.states.registry != registry {
		t.Fatal("terminal server did not retain the shared parent registry")
	}
}

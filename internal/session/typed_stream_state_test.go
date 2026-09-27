package session

import (
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestTypedTerminalStreamLifecycleRejectsReservedDuplicateAndReuse(t *testing.T) {
	streams := newTypedTerminalStreamSet()
	if err := streams.reserve(protocol.MinTypedStreamID - 1); !errors.Is(err, errTypedStreamIDReserved) {
		t.Fatalf("reserve legacy stream error = %v", err)
	}
	if err := streams.reserve(protocol.MinTypedStreamID); err != nil {
		t.Fatal(err)
	}
	if err := streams.reserve(protocol.MinTypedStreamID); !errors.Is(err, errTypedStreamDuplicate) {
		t.Fatalf("duplicate reserve error = %v", err)
	}
	if streams.isOpen(protocol.MinTypedStreamID) {
		t.Fatal("opening stream reported open")
	}
	if err := streams.accept(protocol.MinTypedStreamID); err != nil {
		t.Fatal(err)
	}
	if !streams.isOpen(protocol.MinTypedStreamID) {
		t.Fatal("accepted stream not open")
	}
	if err := streams.close(protocol.MinTypedStreamID); err != nil {
		t.Fatal(err)
	}
	if streams.isOpen(protocol.MinTypedStreamID) {
		t.Fatal("closed stream reported open")
	}
	if err := streams.reserve(protocol.MinTypedStreamID); !errors.Is(err, errTypedStreamDuplicate) {
		t.Fatalf("stream ID reuse error = %v", err)
	}
}

func TestTypedTerminalStreamLimitIncludesLegacyStream(t *testing.T) {
	streams := newTypedTerminalStreamSet()
	for streamID := protocol.MinTypedStreamID; streamID <= maxTerminalStreamsPerConnection; streamID++ {
		if err := streams.reserve(streamID); err != nil {
			t.Fatalf("reserve %d: %v", streamID, err)
		}
		if err := streams.accept(streamID); err != nil {
			t.Fatalf("accept %d: %v", streamID, err)
		}
	}
	if err := streams.reserve(maxTerminalStreamsPerConnection + 1); !errors.Is(err, errTypedStreamLimit) {
		t.Fatalf("over-limit reserve error = %v", err)
	}

	if err := streams.close(protocol.MinTypedStreamID); err != nil {
		t.Fatal(err)
	}
	if err := streams.reserve(maxTerminalStreamsPerConnection + 1); err != nil {
		t.Fatalf("reserve after close: %v", err)
	}
}

func TestTypedTerminalStreamLifetimeIDLimit(t *testing.T) {
	streams := newTypedTerminalStreamSet()
	for i := 0; i < maxTerminalStreamIDsPerConnection; i++ {
		streamID := protocol.MinTypedStreamID + uint32(i)
		if err := streams.reserve(streamID); err != nil {
			t.Fatalf("reserve %d: %v", streamID, err)
		}
		if err := streams.accept(streamID); err != nil {
			t.Fatalf("accept %d: %v", streamID, err)
		}
		if err := streams.close(streamID); err != nil {
			t.Fatalf("close %d: %v", streamID, err)
		}
	}
	if err := streams.reserve(protocol.MinTypedStreamID + maxTerminalStreamIDsPerConnection); !errors.Is(err, errTypedStreamLimit) {
		t.Fatalf("lifetime over-limit reserve error = %v", err)
	}
}

func TestTypedTerminalStreamCloseAllPreservesNoReuseInvariant(t *testing.T) {
	streams := newTypedTerminalStreamSet()
	for _, id := range []uint32{protocol.MinTypedStreamID, 7} {
		if err := streams.reserve(id); err != nil {
			t.Fatal(err)
		}
		if err := streams.accept(id); err != nil {
			t.Fatal(err)
		}
	}
	streams.closeAll()
	if streams.open != 0 || streams.isOpen(protocol.MinTypedStreamID) || streams.isOpen(7) {
		t.Fatalf("closeAll left state open: %#v", streams)
	}
	if err := streams.reserve(7); !errors.Is(err, errTypedStreamDuplicate) {
		t.Fatalf("closed stream ID reused: %v", err)
	}
}

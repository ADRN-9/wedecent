package session

import (
	"errors"
	"testing"
)

func TestTypedTerminalStreamLifecycleRejectsReservedDuplicateAndReuse(t *testing.T) {
	streams := newTypedTerminalStreamSet()
	if err := streams.reserve(terminalStreamID); !errors.Is(err, errTypedStreamIDReserved) {
		t.Fatalf("reserve stream 1 error = %v", err)
	}
	if err := streams.reserve(2); err != nil {
		t.Fatal(err)
	}
	if err := streams.reserve(2); !errors.Is(err, errTypedStreamDuplicate) {
		t.Fatalf("duplicate reserve error = %v", err)
	}
	if streams.isOpen(2) {
		t.Fatal("opening stream reported open")
	}
	if err := streams.accept(2); err != nil {
		t.Fatal(err)
	}
	if !streams.isOpen(2) {
		t.Fatal("accepted stream not open")
	}
	if err := streams.close(2); err != nil {
		t.Fatal(err)
	}
	if streams.isOpen(2) {
		t.Fatal("closed stream reported open")
	}
	if err := streams.reserve(2); !errors.Is(err, errTypedStreamDuplicate) {
		t.Fatalf("stream ID reuse error = %v", err)
	}
}

func TestTypedTerminalStreamLimitIncludesLegacyStream(t *testing.T) {
	streams := newTypedTerminalStreamSet()
	for streamID := uint32(2); streamID <= maxTerminalStreamsPerConnection; streamID++ {
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

	if err := streams.close(2); err != nil {
		t.Fatal(err)
	}
	if err := streams.reserve(maxTerminalStreamsPerConnection + 1); err != nil {
		t.Fatalf("reserve after close: %v", err)
	}
}

func TestTypedTerminalStreamCloseAllPreservesNoReuseInvariant(t *testing.T) {
	streams := newTypedTerminalStreamSet()
	for _, id := range []uint32{2, 7} {
		if err := streams.reserve(id); err != nil {
			t.Fatal(err)
		}
		if err := streams.accept(id); err != nil {
			t.Fatal(err)
		}
	}
	streams.closeAll()
	if streams.open != 0 || streams.isOpen(2) || streams.isOpen(7) {
		t.Fatalf("closeAll left state open: %#v", streams)
	}
	if err := streams.reserve(7); !errors.Is(err, errTypedStreamDuplicate) {
		t.Fatalf("closed stream ID reused: %v", err)
	}
}

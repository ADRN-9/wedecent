package protocol

import "testing"

func TestTypedStreamIDOneRemainsReservedForLegacyTerminal(t *testing.T) {
	if err := ValidateStreamOpen(1, StreamOpen{Kind: StreamKindTerminal, Cols: 80, Rows: 24, InitialWindow: 1}); err == nil {
		t.Fatal("typed stream open accepted legacy stream ID 1")
	}
	if err := ValidateStreamAccepted(1, StreamAccepted{InitialWindow: 1}); err == nil {
		t.Fatal("typed stream accept accepted legacy stream ID 1")
	}
	if err := ValidateStreamData(1, []byte{1}); err == nil {
		t.Fatal("typed stream data accepted legacy stream ID 1")
	}
	if err := ValidateStreamResize(1, Resize{Cols: 80, Rows: 24}); err == nil {
		t.Fatal("typed stream resize accepted legacy stream ID 1")
	}
	if err := ValidateStreamWindowUpdate(1, StreamWindowUpdate{Bytes: 1}); err == nil {
		t.Fatal("typed stream window update accepted legacy stream ID 1")
	}
	if err := ValidateStreamClose(1, StreamClose{}); err == nil {
		t.Fatal("typed stream close accepted legacy stream ID 1")
	}
	if err := ValidateStreamError(1, StreamError{Code: "closed"}); err == nil {
		t.Fatal("typed stream error accepted legacy stream ID 1")
	}
}

func TestTypedStreamControlBounds(t *testing.T) {
	if err := ValidateStreamAccepted(2, StreamAccepted{InitialWindow: 1}); err != nil {
		t.Fatalf("valid stream accept rejected: %v", err)
	}
	if err := ValidateStreamAccepted(2, StreamAccepted{}); err == nil {
		t.Fatal("zero accepted window allowed")
	}
	if err := ValidateStreamAccepted(2, StreamAccepted{InitialWindow: MaxTypedStreamWindow + 1}); err == nil {
		t.Fatal("oversized accepted window allowed")
	}

	longTerm := make([]byte, MaxTypedStreamTermLength+1)
	if err := ValidateStreamOpen(2, StreamOpen{Kind: StreamKindTerminal, Cols: 80, Rows: 24, Term: string(longTerm), InitialWindow: 1}); err == nil {
		t.Fatal("oversized terminal type allowed")
	}

	if err := ValidateStreamClose(2, StreamClose{Reason: string(make([]byte, MaxTypedStreamCloseReasonLength+1))}); err == nil {
		t.Fatal("oversized close reason allowed")
	}
	if err := ValidateStreamError(2, StreamError{}); err == nil {
		t.Fatal("empty stream error code allowed")
	}
	if err := ValidateStreamError(2, StreamError{Code: string(make([]byte, MaxTypedStreamErrorCodeLength+1))}); err == nil {
		t.Fatal("oversized stream error code allowed")
	}
	if err := ValidateStreamError(2, StreamError{Code: "closed", Message: string(make([]byte, MaxTypedStreamErrorMessageLength+1))}); err == nil {
		t.Fatal("oversized stream error message allowed")
	}
	if err := ValidateStreamError(2, StreamError{Code: "closed", Message: "peer closed"}); err != nil {
		t.Fatalf("valid stream error rejected: %v", err)
	}
}

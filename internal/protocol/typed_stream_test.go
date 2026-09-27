package protocol

import (
	"reflect"
	"testing"
)

func TestLegacyFrameTypeNumbersRemainStable(t *testing.T) {
	legacy := []struct {
		got  Type
		want Type
	}{
		{TypePairRequest, 1},
		{TypePairResponse, 2},
		{TypeOpenSession, 3},
		{TypeSessionAccepted, 4},
		{TypeData, 5},
		{TypeResize, 6},
		{TypeClose, 7},
		{TypeError, 8},
		{TypePing, 9},
		{TypePong, 10},
		{TypeOpenAuthorizedSession, 11},
	}
	for _, tc := range legacy {
		if tc.got != tc.want {
			t.Fatalf("legacy frame type = %d, want %d", tc.got, tc.want)
		}
	}
	if TypeStreamOpen != 12 || TypeStreamAccepted != 13 || TypeStreamData != 14 ||
		TypeStreamWindowUpdate != 15 || TypeStreamClose != 16 || TypeStreamError != 17 {
		t.Fatalf("typed-stream frame IDs are not appended after legacy frames")
	}
}

func TestValidateStreamOpen(t *testing.T) {
	valid := StreamOpen{
		Kind:          StreamKindTerminal,
		Cols:          80,
		Rows:          24,
		Term:          "xterm-256color",
		InitialWindow: 64 << 10,
	}
	if err := ValidateStreamOpen(2, valid); err != nil {
		t.Fatalf("valid stream rejected: %v", err)
	}

	cases := []struct {
		name     string
		streamID uint32
		open     StreamOpen
	}{
		{"zero ID", 0, valid},
		{"unknown kind", 2, StreamOpen{Kind: "file", Cols: 80, Rows: 24, InitialWindow: 1}},
		{"zero cols", 2, StreamOpen{Kind: StreamKindTerminal, Rows: 24, InitialWindow: 1}},
		{"zero rows", 2, StreamOpen{Kind: StreamKindTerminal, Cols: 80, InitialWindow: 1}},
		{"zero window", 2, StreamOpen{Kind: StreamKindTerminal, Cols: 80, Rows: 24}},
		{"oversized window", 2, StreamOpen{Kind: StreamKindTerminal, Cols: 80, Rows: 24, InitialWindow: MaxTypedStreamWindow + 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateStreamOpen(tc.streamID, tc.open); err == nil {
				t.Fatal("invalid stream open accepted")
			}
		})
	}
}

func TestValidateStreamWindowUpdate(t *testing.T) {
	if err := ValidateStreamWindowUpdate(3, StreamWindowUpdate{Bytes: 32 << 10}); err != nil {
		t.Fatalf("valid window update rejected: %v", err)
	}
	for _, tc := range []struct {
		streamID uint32
		bytes    uint32
	}{
		{0, 1},
		{3, 0},
		{3, MaxTypedStreamWindow + 1},
	} {
		if err := ValidateStreamWindowUpdate(tc.streamID, StreamWindowUpdate{Bytes: tc.bytes}); err == nil {
			t.Fatalf("accepted invalid window update: stream=%d bytes=%d", tc.streamID, tc.bytes)
		}
	}
}

func TestTypedStreamMessagesRoundTrip(t *testing.T) {
	want := StreamOpen{
		Kind:          StreamKindTerminal,
		Cols:          132,
		Rows:          43,
		Term:          "xterm-256color",
		InitialWindow: 128 << 10,
	}
	payload, err := JSON(want)
	if err != nil {
		t.Fatal(err)
	}
	var got StreamOpen
	if err := ParseJSON(payload, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

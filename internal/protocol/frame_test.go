package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	want := Frame{Type: TypeData, StreamID: 7, Payload: []byte("hello")}
	if err := WriteFrame(&b, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.StreamID != want.StreamID || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestFrameRejectsOversize(t *testing.T) {
	var b bytes.Buffer
	err := WriteFrame(&b, Frame{Type: TypeData, Payload: make([]byte, MaxPayloadSize+1)})
	if err == nil {
		t.Fatal("expected oversize payload error")
	}
}

func TestConnectionFrameTypesAppendWithoutRenumberingExistingProtocol(t *testing.T) {
	if TypeOpenAuthorizedSession != 11 {
		t.Fatalf("TypeOpenAuthorizedSession = %d, want stable value 11", TypeOpenAuthorizedSession)
	}
	if TypeOpenConnection != 12 || TypeConnectionAccepted != 13 || TypeOpenAuthorizedConnection != 14 {
		t.Fatalf("connection frame values = %d/%d/%d, want 12/13/14", TypeOpenConnection, TypeConnectionAccepted, TypeOpenAuthorizedConnection)
	}
}

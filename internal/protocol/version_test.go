package protocol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestFrameVersionCompatibility(t *testing.T) {
	var encoded bytes.Buffer
	want := Frame{Type: TypePing, StreamID: 9, Payload: []byte("v1")}
	if err := WriteFrame(&encoded, want); err != nil {
		t.Fatal(err)
	}
	wire := encoded.Bytes()
	if wire[2] != Version || Version != 1 {
		t.Fatalf("wire version = %d, Version = %d; want v1", wire[2], Version)
	}
	got, err := ReadFrame(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.StreamID != want.StreamID || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("v1 round trip changed frame: got %#v want %#v", got, want)
	}
}

func TestReadFrameRejectsUnsupportedVersionBeforePayload(t *testing.T) {
	for _, version := range []byte{0, 2, 255} {
		t.Run(string(rune(version)), func(t *testing.T) {
			header := make([]byte, HeaderSize)
			copy(header[:2], magic[:])
			header[2] = version
			header[3] = byte(TypeData)
			binary.BigEndian.PutUint32(header[4:8], 1)
			binary.BigEndian.PutUint32(header[8:12], 4)
			payload := []byte("data")
			r := bytes.NewReader(append(header, payload...))

			_, err := ReadFrame(r)
			if err == nil || !strings.Contains(err.Error(), "unsupported protocol version") {
				t.Fatalf("version %d error = %v", version, err)
			}
			if r.Len() != len(payload) {
				t.Fatalf("unsupported version %d consumed payload: %d bytes remain, want %d", version, r.Len(), len(payload))
			}
		})
	}
}

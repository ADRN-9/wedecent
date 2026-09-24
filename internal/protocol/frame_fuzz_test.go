package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzReadFrame(f *testing.F) {
	var valid bytes.Buffer
	if err := WriteFrame(&valid, Frame{Type: TypeData, StreamID: 7, Payload: []byte("hello")}); err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add([]byte{'W', 'D', Version})
	f.Add([]byte("not-a-frame"))

	oversize := make([]byte, HeaderSize)
	copy(oversize[:2], magic[:])
	oversize[2] = Version
	oversize[3] = byte(TypeData)
	binary.BigEndian.PutUint32(oversize[8:12], MaxPayloadSize+1)
	f.Add(oversize)

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ReadFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(got.Payload) > MaxPayloadSize {
			t.Fatalf("decoder returned oversized payload: %d", len(got.Payload))
		}

		var encoded bytes.Buffer
		if err := WriteFrame(&encoded, got); err != nil {
			t.Fatalf("re-encode accepted frame: %v", err)
		}
		roundTrip, err := ReadFrame(&encoded)
		if err != nil {
			t.Fatalf("decode re-encoded frame: %v", err)
		}
		if roundTrip.Type != got.Type || roundTrip.StreamID != got.StreamID || !bytes.Equal(roundTrip.Payload, got.Payload) {
			t.Fatalf("frame changed after normalized round trip: got %#v, roundTrip %#v", got, roundTrip)
		}
	})
}

package relayproto

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func FuzzRead(f *testing.F) {
	for _, msg := range []Message{
		{Type: TypeChallenge, Challenge: "nonce"},
		{Type: TypeRegister, DeviceID: "wd_device", PublicKey: "key", Signature: "sig"},
		{Type: TypeConnect, DeviceID: "wd_peer"},
		{Type: TypeError, Code: "denied", Error: "not authorized"},
	} {
		var encoded bytes.Buffer
		if err := Write(&encoded, msg); err != nil {
			f.Fatal(err)
		}
		f.Add(encoded.Bytes())
	}
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 1, '{'})

	oversize := make([]byte, 4)
	binary.BigEndian.PutUint32(oversize, MaxMessage+1)
	f.Add(oversize)

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := Read(bytes.NewReader(data))
		if err != nil {
			return
		}

		var encoded bytes.Buffer
		if err := Write(&encoded, got); err != nil {
			t.Fatalf("re-encode accepted relay control message: %v", err)
		}
		roundTrip, err := Read(&encoded)
		if err != nil {
			t.Fatalf("decode re-encoded relay control message: %v", err)
		}
		if !reflect.DeepEqual(roundTrip, got) {
			t.Fatalf("relay control message changed after normalized round trip: got %#v, roundTrip %#v", got, roundTrip)
		}
	})
}

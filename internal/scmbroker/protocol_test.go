package scmbroker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func frame(s string) []byte {
	b := []byte(s); out := make([]byte, 4+len(b)); binary.BigEndian.PutUint32(out, uint32(len(b))); copy(out[4:], b); return out
}

func TestReadRequestAcceptsOnlyReadOnlyAllowlist(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	req, err := ReadRequest(bytes.NewReader(frame(`{"version":1,"request_id":"`+id+`","operation":"health"}`)))
	if err != nil { t.Fatal(err) }
	if req.Operation != OpHealth { t.Fatalf("operation = %q", req.Operation) }
	for _, raw := range []string{
		`{"version":1,"request_id":"`+id+`","operation":"mutate"}`,
		`{"version":1,"version":1,"request_id":"`+id+`","operation":"health"}`,
		`{"version":1,"request_id":"`+id+`","operation":"health","extra":true}`,
		`{"version":1,"request_id":"`+id+`","operation":"health"} {}`,
	} {
		if _, err := ReadRequest(bytes.NewReader(frame(raw))); !errors.Is(err, ErrInvalidMessage) { t.Fatalf("ReadRequest(%s) error = %v", raw, err) }
	}
}

func TestReadRequestRejectsOversizedAndTruncatedFrames(t *testing.T) {
	var header [4]byte; binary.BigEndian.PutUint32(header[:], MaxRequestBytes+1)
	if _, err := ReadRequest(bytes.NewReader(header[:])); !errors.Is(err, ErrInvalidMessage) { t.Fatalf("oversize error = %v", err) }
	if _, err := ReadRequest(bytes.NewReader([]byte{0,0,0,4,'{'})); !errors.Is(err, ErrInvalidMessage) { t.Fatalf("truncated error = %v", err) }
}

func TestWriteResponseBoundsFrame(t *testing.T) {
	var b bytes.Buffer
	if err := WriteResponse(&b, Response{RequestID:"x", OK:true}); err != nil { t.Fatal(err) }
	if binary.BigEndian.Uint32(b.Bytes()[:4]) != uint32(b.Len()-4) { t.Fatal("incorrect response length") }
}

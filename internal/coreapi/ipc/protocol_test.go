package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestRequestRoundTrip(t *testing.T) {
	params, err := json.Marshal(v1.GetDeviceRequest{DeviceID: "wd_aaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
	want := Request{
		Version: v1.Version,
		ID:      "request-1",
		Method:  v1.MethodDeviceGet,
		Params:  params,
	}

	var wire bytes.Buffer
	if err := WriteRequest(&wire, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRequest(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || got.ID != want.ID || got.Method != want.Method || !bytes.Equal(got.Params, want.Params) {
		t.Fatalf("request = %#v, want %#v", got, want)
	}
}

func TestReadRequestRejectsOversizedFrameBeforeReadingPayload(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxFrameBytes+1)

	_, err := ReadRequest(bytes.NewReader(header[:]))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func TestReadRequestRejectsUnknownAndTrailingJSON(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"version":"v1","id":"1","method":"status.get","unknown":true}`),
		[]byte(`{"version":"v1","id":"1","method":"status.get"} {}`),
	} {
		// Convert the source literals to valid JSON. The backslash-free payloads
		// ensure these cases fail for the intended unknown/trailing-value rules,
		// not because the first JSON token is malformed.
		payload = bytes.ReplaceAll(payload, []byte(`\"`), []byte(`"`))
		_, err := ReadRequest(bytes.NewReader(frame(payload)))
		if !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("payload %q error = %v", payload, err)
		}
	}
}

func TestRequestIdentifiersRejectControlCharacters(t *testing.T) {
	var wire bytes.Buffer
	err := WriteRequest(&wire, Request{
		Version: v1.Version,
		ID:      "request\nsecret",
		Method:  v1.MethodStatusGet,
	})
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("error = %v", err)
	}
}

func TestResponseRequiresExactlyOneResultOrError(t *testing.T) {
	result := json.RawMessage(`{"ok":true}`)
	result = bytes.ReplaceAll(result, []byte(`\"`), []byte(`"`))
	cases := []Response{
		{Version: v1.Version, ID: "1"},
		{
			Version: v1.Version,
			ID:      "1",
			Result:  result,
			Error:   &ResponseError{Code: ErrorInternal, Message: "internal error"},
		},
	}
	for _, response := range cases {
		var wire bytes.Buffer
		if err := WriteResponse(&wire, response); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("response %#v error = %v", response, err)
		}
	}
}

func TestMarshalResultRejectsOversizedPayload(t *testing.T) {
	_, err := MarshalResult(string(bytes.Repeat([]byte("x"), MaxFrameBytes)))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func frame(payload []byte) []byte {
	wire := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(wire[:4], uint32(len(payload)))
	copy(wire[4:], payload)
	return wire
}

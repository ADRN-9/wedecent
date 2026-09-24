package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func TestProtocolVersionCompatibilityLocalCoreIPC(t *testing.T) {
	t.Parallel()

	var requestWire bytes.Buffer
	request := Request{Version: v1.Version, ID: "compat-request", Method: v1.MethodStatusGet}
	if err := WriteRequest(&requestWire, request); err != nil {
		t.Fatalf("WriteRequest(v1) error: %v", err)
	}
	if got, err := ReadRequest(bytes.NewReader(requestWire.Bytes())); err != nil {
		t.Fatalf("ReadRequest(v1) error: %v", err)
	} else if got.Version != v1.Version {
		t.Fatalf("ReadRequest(v1).Version = %q, want %q", got.Version, v1.Version)
	}

	var responseWire bytes.Buffer
	response := Response{Version: v1.Version, ID: request.ID, Result: []byte(`{}`)}
	if err := WriteResponse(&responseWire, response); err != nil {
		t.Fatalf("WriteResponse(v1) error: %v", err)
	}
	if got, err := ReadResponse(bytes.NewReader(responseWire.Bytes())); err != nil {
		t.Fatalf("ReadResponse(v1) error: %v", err)
	} else if got.Version != v1.Version {
		t.Fatalf("ReadResponse(v1).Version = %q, want %q", got.Version, v1.Version)
	}

	for _, version := range []string{"v0", "v2", "2", ""} {
		version := version
		t.Run(fmt.Sprintf("reject_request_%q", version), func(t *testing.T) {
			wire := rawCompatibilityFrame(fmt.Sprintf("{\"version\":%q,\"id\":\"compat-request\",\"method\":\"status.get\"}", version))
			_, err := ReadRequest(bytes.NewReader(wire))
			if !errors.Is(err, ErrInvalidMessage) || !strings.Contains(err.Error(), "unsupported version") {
				t.Fatalf("ReadRequest(version=%q) error = %v, want unsupported-version ErrInvalidMessage", version, err)
			}
		})
		t.Run(fmt.Sprintf("reject_response_%q", version), func(t *testing.T) {
			wire := rawCompatibilityFrame(fmt.Sprintf("{\"version\":%q,\"id\":\"compat-request\",\"result\":{}}", version))
			_, err := ReadResponse(bytes.NewReader(wire))
			if !errors.Is(err, ErrInvalidMessage) || !strings.Contains(err.Error(), "unsupported version") {
				t.Fatalf("ReadResponse(version=%q) error = %v, want unsupported-version ErrInvalidMessage", version, err)
			}
		})
	}
}

func rawCompatibilityFrame(payload string) []byte {
	wire := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(wire[:4], uint32(len(payload)))
	copy(wire[4:], payload)
	return wire
}

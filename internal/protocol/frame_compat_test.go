package protocol

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestProtocolVersionCompatibilityFrame(t *testing.T) {
	t.Parallel()

	original := Frame{Type: TypePing, StreamID: 7, Payload: []byte("compat")}
	var wire bytes.Buffer
	if err := WriteFrame(&wire, original); err != nil {
		t.Fatalf("WriteFrame() error: %v", err)
	}
	encoded := wire.Bytes()
	if got := encoded[2]; got != Version {
		t.Fatalf("encoded version = %d, want %d", got, Version)
	}

	decoded, err := ReadFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("ReadFrame(v1) error: %v", err)
	}
	if decoded.Type != original.Type || decoded.StreamID != original.StreamID || !bytes.Equal(decoded.Payload, original.Payload) {
		t.Fatalf("ReadFrame(v1) = %+v, want %+v", decoded, original)
	}

	for _, version := range []byte{0, Version + 1, 255} {
		version := version
		t.Run(fmt.Sprintf("reject_version_%d", version), func(t *testing.T) {
			mutated := append([]byte(nil), encoded...)
			mutated[2] = version
			_, err := ReadFrame(bytes.NewReader(mutated))
			if err == nil || !strings.Contains(err.Error(), "unsupported protocol version") {
				t.Fatalf("ReadFrame(version=%d) error = %v, want unsupported-version rejection", version, err)
			}
		})
	}
}

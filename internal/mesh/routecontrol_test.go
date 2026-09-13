package mesh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRouteOpenRequestRoundTripDoesNotConsumeTunnelBytes(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	req := RouteOpenRequest{
		Route: Route{
			ID:          "route-a-b-c",
			Source:      "wd_a",
			Destination: "wd_c",
			ExpiresAt:   now.Add(time.Minute),
			Hops: []RouteHop{
				{From: "wd_a", To: "wd_b", Transport: TransportLAN},
				{From: "wd_b", To: "wd_c", Transport: TransportInternet},
			},
		},
	}

	var wire bytes.Buffer
	if err := WriteRouteOpenRequest(&wire, req); err != nil {
		t.Fatalf("WriteRouteOpenRequest() error: %v", err)
	}

	innerTLS := []byte{0x16, 0x03, 0x03, 0x00, 0x2a, 0xde, 0xad, 0xbe, 0xef}
	if _, err := wire.Write(innerTLS); err != nil {
		t.Fatalf("append tunnel bytes: %v", err)
	}

	got, err := ReadRouteOpenRequest(&wire)
	if err != nil {
		t.Fatalf("ReadRouteOpenRequest() error: %v", err)
	}

	if got.Route.ID != req.Route.ID ||
		got.Route.Source != req.Route.Source ||
		got.Route.Destination != req.Route.Destination ||
		len(got.Route.Hops) != 2 {
		t.Fatalf("route-open request changed during round trip: %+v", got)
	}

	remaining := make([]byte, len(innerTLS))
	if _, err := io.ReadFull(&wire, remaining); err != nil {
		t.Fatalf("read preserved tunnel bytes: %v", err)
	}
	if !bytes.Equal(remaining, innerTLS) {
		t.Fatalf("tunnel bytes changed: got %x want %x", remaining, innerTLS)
	}
}

func TestRouteOpenResponseRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []RouteOpenResponse{
		{Accepted: true},
		{Accepted: false, Code: RouteOpenCodeDenied},
		{Accepted: false, Code: RouteOpenCodeBusy},
		{Accepted: false, Code: RouteOpenCodeUnavailable},
		{Accepted: false, Code: RouteOpenCodeInvalidRequest},
	}

	for _, want := range tests {
		want := want
		t.Run(string(want.Code), func(t *testing.T) {
			var wire bytes.Buffer

			if err := WriteRouteOpenResponse(&wire, want); err != nil {
				t.Fatalf("WriteRouteOpenResponse() error: %v", err)
			}
			got, err := ReadRouteOpenResponse(&wire)
			if err != nil {
				t.Fatalf("ReadRouteOpenResponse() error: %v", err)
			}
			if got != want {
				t.Fatalf("response = %+v, want %+v", got, want)
			}
		})
	}
}

func TestRouteOpenResponseRejectsInvalidStates(t *testing.T) {
	t.Parallel()

	tests := []RouteOpenResponse{
		{Accepted: true, Code: RouteOpenCodeDenied},
		{Accepted: false},
		{Accepted: false, Code: "future-unknown-code"},
	}

	for _, resp := range tests {
		var wire bytes.Buffer
		if err := WriteRouteOpenResponse(&wire, resp); err == nil {
			t.Fatalf("invalid response accepted: %+v", resp)
		}
	}
}

func TestRouteControlRejectsWrongMagic(t *testing.T) {
	t.Parallel()

	wire := rawRouteControlFrame(
		[4]byte{'N', 'O', 'P', 'E'},
		RouteControlVersion,
		routeControlOpen,
		[]byte(`{"route":{}}`),
	)

	if _, err := ReadRouteOpenRequest(bytes.NewReader(wire)); err == nil {
		t.Fatal("route-control frame with wrong magic accepted")
	}
}

func TestRouteControlRejectsWrongVersion(t *testing.T) {
	t.Parallel()

	wire := rawRouteControlFrame(
		routeControlMagic,
		RouteControlVersion+1,
		routeControlOpen,
		[]byte(`{"route":{}}`),
	)

	if _, err := ReadRouteOpenRequest(bytes.NewReader(wire)); err == nil {
		t.Fatal("route-control frame with unsupported version accepted")
	}
}

func TestRouteControlRejectsWrongMessageType(t *testing.T) {
	t.Parallel()

	wire := rawRouteControlFrame(
		routeControlMagic,
		RouteControlVersion,
		routeControlResponse,
		[]byte(`{"accepted":true}`),
	)

	if _, err := ReadRouteOpenRequest(bytes.NewReader(wire)); err == nil {
		t.Fatal("unexpected route-control message type accepted")
	}
}

func TestRouteControlRejectsNonZeroReservedField(t *testing.T) {
	t.Parallel()

	wire := rawRouteControlFrame(
		routeControlMagic,
		RouteControlVersion,
		routeControlOpen,
		[]byte(`{"route":{}}`),
	)
	wire[6] = 1

	if _, err := ReadRouteOpenRequest(bytes.NewReader(wire)); err == nil {
		t.Fatal("non-zero reserved route-control field accepted")
	}
}

func TestRouteControlRejectsOversizedPayloadBeforeAllocation(t *testing.T) {
	t.Parallel()

	header := make([]byte, routeControlHeaderSize)
	copy(header[:4], routeControlMagic[:])
	header[4] = RouteControlVersion
	header[5] = byte(routeControlOpen)
	binary.BigEndian.PutUint32(header[8:12], MaxRouteControlPayload+1)

	if _, err := ReadRouteOpenRequest(bytes.NewReader(header)); err == nil {
		t.Fatal("oversized route-control payload accepted")
	}
}

func TestRouteControlWriterRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	err := WriteRouteOpenResponse(io.Discard, RouteOpenResponse{
		Accepted: false,
		Code:     RouteOpenCode(strings.Repeat("x", MaxRouteControlPayload)),
	})
	if err == nil {
		t.Fatal("oversized route-control payload written")
	}
}

func TestRouteControlRejectsUnknownJSONFields(t *testing.T) {
	t.Parallel()

	wire := rawRouteControlFrame(
		routeControlMagic,
		RouteControlVersion,
		routeControlOpen,
		[]byte(`{"route":{},"unexpected":true}`),
	)

	_, err := ReadRouteOpenRequest(bytes.NewReader(wire))
	if err == nil {
		t.Fatal("route-control request with unknown JSON field accepted")
	}
}

func TestRouteControlRejectsTruncatedPayload(t *testing.T) {
	t.Parallel()

	wire := rawRouteControlFrame(
		routeControlMagic,
		RouteControlVersion,
		routeControlOpen,
		[]byte(`{"route":{}}`),
	)
	wire = wire[:len(wire)-1]

	_, err := ReadRouteOpenRequest(bytes.NewReader(wire))
	if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated route-control payload error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func rawRouteControlFrame(
	magic [4]byte,
	version byte,
	typ routeControlType,
	payload []byte,
) []byte {
	header := make([]byte, routeControlHeaderSize)
	copy(header[:4], magic[:])
	header[4] = version
	header[5] = byte(typ)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))

	frame := append([]byte(nil), header...)
	frame = append(frame, payload...)
	return frame
}

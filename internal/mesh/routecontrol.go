package mesh

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	RouteControlVersion    = 2
	MaxRouteControlPayload = 64 << 10 // 64 KiB

	routeControlHeaderSize = 12
)

var routeControlMagic = [4]byte{'W', 'D', 'R', 'T'}

type routeControlType uint8

const (
	routeControlOpen routeControlType = 1 + iota
	routeControlResponse
)

// RouteOpenRequest is sent over an already authenticated neighboring mesh link.
//
// After an accepted response, the same link stops carrying route-control
// messages and becomes the opaque endpoint-to-endpoint byte tunnel.
type RouteOpenRequest struct {
	Route         Route              `json:"route"`
	Authorization RouteAuthorization `json:"authorization"`
}

// RouteOpenCode is a stable, non-sensitive route-open result code.
type RouteOpenCode string

const (
	RouteOpenCodeInvalidRequest RouteOpenCode = "invalid_request"
	RouteOpenCodeDenied         RouteOpenCode = "route_denied"
	RouteOpenCodeBusy           RouteOpenCode = "router_busy"
	RouteOpenCodeUnavailable    RouteOpenCode = "route_unavailable"
)

// RouteOpenResponse acknowledges or rejects a route-open request.
//
// Detailed authorization errors are intentionally not sent to the requester.
type RouteOpenResponse struct {
	Accepted bool          `json:"accepted"`
	Code     RouteOpenCode `json:"code,omitempty"`
}

func WriteRouteOpenRequest(w io.Writer, req RouteOpenRequest) error {
	return writeRouteControlJSON(w, routeControlOpen, req)
}

func ReadRouteOpenRequest(r io.Reader) (RouteOpenRequest, error) {
	payload, err := readRouteControlFrame(r, routeControlOpen)
	if err != nil {
		return RouteOpenRequest{}, err
	}

	var req RouteOpenRequest
	if err := decodeRouteControlJSON(payload, &req); err != nil {
		return RouteOpenRequest{}, fmt.Errorf("mesh: decode route-open request: %w", err)
	}
	return req, nil
}

func WriteRouteOpenResponse(w io.Writer, resp RouteOpenResponse) error {
	if err := resp.validate(); err != nil {
		return err
	}
	return writeRouteControlJSON(w, routeControlResponse, resp)
}

func ReadRouteOpenResponse(r io.Reader) (RouteOpenResponse, error) {
	payload, err := readRouteControlFrame(r, routeControlResponse)
	if err != nil {
		return RouteOpenResponse{}, err
	}

	var resp RouteOpenResponse
	if err := decodeRouteControlJSON(payload, &resp); err != nil {
		return RouteOpenResponse{}, fmt.Errorf("mesh: decode route-open response: %w", err)
	}
	if err := resp.validate(); err != nil {
		return RouteOpenResponse{}, err
	}
	return resp, nil
}

func (r RouteOpenResponse) validate() error {
	if r.Accepted {
		if r.Code != "" {
			return errors.New("mesh: accepted route-open response must not contain an error code")
		}
		return nil
	}

	switch r.Code {
	case RouteOpenCodeInvalidRequest,
		RouteOpenCodeDenied,
		RouteOpenCodeBusy,
		RouteOpenCodeUnavailable:
		return nil
	case "":
		return errors.New("mesh: rejected route-open response requires an error code")
	default:
		return fmt.Errorf("mesh: unsupported route-open response code %q", r.Code)
	}
}

func writeRouteControlJSON(w io.Writer, typ routeControlType, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("mesh: encode route-control payload: %w", err)
	}
	return writeRouteControlFrame(w, typ, payload)
}

func writeRouteControlFrame(w io.Writer, typ routeControlType, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("mesh: empty route-control payload")
	}
	if len(payload) > MaxRouteControlPayload {
		return fmt.Errorf("mesh: route-control payload exceeds %d bytes", MaxRouteControlPayload)
	}

	header := make([]byte, routeControlHeaderSize)
	copy(header[:4], routeControlMagic[:])
	header[4] = RouteControlVersion
	header[5] = byte(typ)
	// header[6:8] is reserved and must remain zero.
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))

	if err := writeRouteControlAll(w, header); err != nil {
		return err
	}
	return writeRouteControlAll(w, payload)
}

func readRouteControlFrame(r io.Reader, expected routeControlType) ([]byte, error) {
	header := make([]byte, routeControlHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("mesh: read route-control header: %w", err)
	}

	if !bytes.Equal(header[:4], routeControlMagic[:]) {
		return nil, errors.New("mesh: invalid route-control magic")
	}
	if header[4] != RouteControlVersion {
		return nil, fmt.Errorf("mesh: unsupported route-control version %d", header[4])
	}
	if routeControlType(header[5]) != expected {
		return nil, fmt.Errorf("mesh: unexpected route-control message type %d", header[5])
	}
	if header[6] != 0 || header[7] != 0 {
		return nil, errors.New("mesh: non-zero route-control reserved field")
	}

	length := binary.BigEndian.Uint32(header[8:12])
	if length == 0 {
		return nil, errors.New("mesh: empty route-control payload")
	}
	if length > MaxRouteControlPayload {
		return nil, fmt.Errorf("mesh: route-control payload exceeds %d bytes", MaxRouteControlPayload)
	}

	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("mesh: read route-control payload: %w", err)
	}
	return payload, nil
}

func decodeRouteControlJSON(payload []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(v); err != nil {
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func writeRouteControlAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return fmt.Errorf("mesh: write route-control message: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

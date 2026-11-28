package scmbroker

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	ProtocolVersion  = 1
	MaxRequestBytes  = 64 * 1024
	MaxResponseBytes = 16 * 1024
)

var ErrInvalidMessage = errors.New("scm broker: invalid message")

type Operation string

const (
	OpHealth Operation = "health"
	OpQuery  Operation = "query"
)

type Request struct {
	Version   uint16          `json:"version"`
	RequestID string          `json:"request_id"`
	Operation Operation       `json:"operation"`
	Payload   json.RawMessage `json:"payload"`
}

type Response struct {
	Version   uint16 `json:"version"`
	RequestID string `json:"request_id"`
	OK        bool   `json:"ok"`
	Code      string `json:"code"`
}

func ReadRequest(r io.Reader) (Request, error) {
	var zero Request
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return zero, fmt.Errorf("%w: header: %v", ErrInvalidMessage, err)
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxRequestBytes {
		return zero, fmt.Errorf("%w: frame length", ErrInvalidMessage)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return zero, fmt.Errorf("%w: truncated frame", ErrInvalidMessage)
	}
	if !utf8.Valid(buf) {
		return zero, fmt.Errorf("%w: utf-8", ErrInvalidMessage)
	}
	if err := rejectDuplicateKeys(buf); err != nil {
		return zero, err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return zero, fmt.Errorf("%w: schema: %v", ErrInvalidMessage, err)
	}
	if dec.Decode(new(any)) != io.EOF {
		return zero, fmt.Errorf("%w: trailing data", ErrInvalidMessage)
	}
	if req.Version != ProtocolVersion || len(req.RequestID) != 32 || !isHex(req.RequestID) {
		return zero, fmt.Errorf("%w: version or request id", ErrInvalidMessage)
	}
	if req.Operation != OpHealth && req.Operation != OpQuery {
		return zero, fmt.Errorf("%w: operation not allowed", ErrInvalidMessage)
	}
	if len(req.Payload) != 0 && string(req.Payload) != "null" && string(req.Payload) != "{}" {
		return zero, fmt.Errorf("%w: payload not allowed", ErrInvalidMessage)
	}
	return req, nil
}

func WriteResponse(w io.Writer, response Response) error {
	response.Version = ProtocolVersion
	body, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > MaxResponseBytes {
		return ErrInvalidMessage
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, body)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return ErrInvalidMessage
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return ErrInvalidMessage
		}
	}
	if err := walk(); err != nil {
		return fmt.Errorf("%w: duplicate or malformed JSON", ErrInvalidMessage)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON", ErrInvalidMessage)
	}
	return nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

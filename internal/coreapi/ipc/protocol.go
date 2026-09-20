package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const MaxFrameBytes = 64 << 10

var (
	ErrFrameTooLarge  = errors.New("coreapi ipc: frame exceeds maximum size")
	ErrInvalidMessage = errors.New("coreapi ipc: invalid message")
)

type Request struct {
	Version string          `json:"version"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	Version string          `json:"version"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ResponseError  `json:"error,omitempty"`
}

func ReadRequest(r io.Reader) (Request, error) {
	payload, err := readFrame(r)
	if err != nil {
		return Request{}, err
	}
	defer wipe(payload)

	var req Request
	if err := decodeStrict(payload, &req); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	if err := validateRequest(req); err != nil {
		return Request{}, err
	}
	return req, nil
}

func WriteRequest(w io.Writer, req Request) error {
	if err := validateRequest(req); err != nil {
		return err
	}
	return writeJSONFrame(w, req)
}

func ReadResponse(r io.Reader) (Response, error) {
	payload, err := readFrame(r)
	if err != nil {
		return Response{}, err
	}

	var response Response
	if err := decodeStrict(payload, &response); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	if err := validateResponse(response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func WriteResponse(w io.Writer, response Response) error {
	if err := validateResponse(response); err != nil {
		return err
	}
	return writeJSONFrame(w, response)
}

func MarshalResult(value any) (json.RawMessage, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	return data, nil
}

func DecodeParams(raw json.RawMessage, value any) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: params are required", ErrInvalidMessage)
	}
	if err := decodeStrict(raw, value); err != nil {
		return fmt.Errorf("%w: invalid params: %v", ErrInvalidMessage, err)
	}
	return nil
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 {
		return nil, fmt.Errorf("%w: empty frame", ErrInvalidMessage)
	}
	if size > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeJSONFrame(w io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		return fmt.Errorf("%w: empty frame", ErrInvalidMessage)
	}
	if len(payload) > MaxFrameBytes {
		return ErrFrameTooLarge
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func decodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validateRequest(req Request) error {
	if req.Version != v1.Version {
		return fmt.Errorf("%w: unsupported version", ErrInvalidMessage)
	}
	if !validIdentifier(req.ID, 128) {
		return fmt.Errorf("%w: invalid request id", ErrInvalidMessage)
	}
	if !validIdentifier(req.Method, 64) {
		return fmt.Errorf("%w: invalid method", ErrInvalidMessage)
	}
	return nil
}

func validateResponse(response Response) error {
	if response.Version != v1.Version {
		return fmt.Errorf("%w: unsupported version", ErrInvalidMessage)
	}
	if !validIdentifier(response.ID, 128) {
		return fmt.Errorf("%w: invalid response id", ErrInvalidMessage)
	}
	if len(response.Result) > 0 && response.Error != nil {
		return fmt.Errorf("%w: response cannot contain both result and error", ErrInvalidMessage)
	}
	if len(response.Result) == 0 && response.Error == nil {
		return fmt.Errorf("%w: response requires result or error", ErrInvalidMessage)
	}
	if response.Error != nil {
		if !validIdentifier(response.Error.Code, 64) || strings.TrimSpace(response.Error.Message) == "" {
			return fmt.Errorf("%w: invalid response error", ErrInvalidMessage)
		}
	}
	return nil
}

func validIdentifier(value string, max int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) == -1
}

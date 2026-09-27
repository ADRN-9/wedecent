package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	MaxTypedStreamWindowBytes = 4 << 20
	MaxTypedStreamTermBytes   = 128
	MaxTypedStreamReasonBytes = 128
)

type StreamKind string

const (
	StreamKindTerminal StreamKind = "terminal"
)

type OpenStream struct {
	Kind               StreamKind `json:"kind"`
	ReceiveWindowBytes uint32     `json:"receive_window_bytes"`
	Cols               uint16     `json:"cols"`
	Rows               uint16     `json:"rows"`
	Term               string     `json:"term"`
}

type StreamAccepted struct {
	ReceiveWindowBytes uint32 `json:"receive_window_bytes"`
}

type StreamWindow struct {
	CreditBytes uint32 `json:"credit_bytes"`
}

type StreamClose struct {
	Reason string `json:"reason,omitempty"`
}

func IsTypedStreamType(t Type) bool {
	switch t {
	case TypeOpenStream, TypeStreamAccepted, TypeStreamData, TypeStreamResize, TypeStreamClose, TypeStreamWindow:
		return true
	default:
		return false
	}
}

// ValidateTypedStreamFrame validates a typed-stream frame only after the caller
// has established that typed-streams-v1 was explicitly negotiated. Runtime
// session code must reject these frames before negotiation rather than calling
// this function as an implicit capability check.
func ValidateTypedStreamFrame(frame Frame) error {
	if !IsTypedStreamType(frame.Type) {
		return errors.New("not a typed-stream frame")
	}
	if frame.StreamID == 0 {
		return errors.New("typed stream ID must be non-zero")
	}

	switch frame.Type {
	case TypeOpenStream:
		var open OpenStream
		if err := parseTypedStreamJSON(frame.Payload, &open); err != nil {
			return err
		}
		return validateOpenStream(open)
	case TypeStreamAccepted:
		var accepted StreamAccepted
		if err := parseTypedStreamJSON(frame.Payload, &accepted); err != nil {
			return err
		}
		return validateWindow(accepted.ReceiveWindowBytes)
	case TypeStreamData:
		if len(frame.Payload) == 0 {
			return errors.New("typed stream data must not be empty")
		}
		return nil
	case TypeStreamResize:
		var resize Resize
		if err := parseTypedStreamJSON(frame.Payload, &resize); err != nil {
			return err
		}
		if resize.Cols == 0 || resize.Rows == 0 {
			return errors.New("typed terminal stream size must be non-zero")
		}
		return nil
	case TypeStreamClose:
		var closeMessage StreamClose
		if err := parseTypedStreamJSON(frame.Payload, &closeMessage); err != nil {
			return err
		}
		if !validOptionalVisible(closeMessage.Reason, MaxTypedStreamReasonBytes) {
			return errors.New("typed stream close reason is invalid")
		}
		return nil
	case TypeStreamWindow:
		var window StreamWindow
		if err := parseTypedStreamJSON(frame.Payload, &window); err != nil {
			return err
		}
		return validateWindow(window.CreditBytes)
	default:
		return errors.New("unsupported typed-stream frame")
	}
}

func validateOpenStream(open OpenStream) error {
	if open.Kind != StreamKindTerminal {
		return fmt.Errorf("unsupported typed stream kind %q", open.Kind)
	}
	if err := validateWindow(open.ReceiveWindowBytes); err != nil {
		return err
	}
	if open.Cols == 0 || open.Rows == 0 {
		return errors.New("typed terminal stream size must be non-zero")
	}
	if !validRequiredVisible(open.Term, MaxTypedStreamTermBytes) {
		return errors.New("typed terminal stream term is invalid")
	}
	return nil
}

func validateWindow(value uint32) error {
	if value == 0 || value > MaxTypedStreamWindowBytes {
		return errors.New("typed stream window is out of range")
	}
	return nil
}

func parseTypedStreamJSON(data []byte, value any) error {
	if len(data) == 0 {
		return errors.New("typed stream payload is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid typed stream payload: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("typed stream payload contains multiple JSON values")
		}
		return fmt.Errorf("invalid typed stream payload: %w", err)
	}
	return nil
}

func validRequiredVisible(value string, maxBytes int) bool {
	return value != "" && value == strings.TrimSpace(value) && validVisible(value, maxBytes)
}

func validOptionalVisible(value string, maxBytes int) bool {
	return value == "" || (value == strings.TrimSpace(value) && validVisible(value, maxBytes))
}

func validVisible(value string, maxBytes int) bool {
	if len(value) > maxBytes {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

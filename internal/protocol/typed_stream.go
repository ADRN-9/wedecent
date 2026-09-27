package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type StreamKind string

const (
	StreamKindTerminal   StreamKind = "terminal"
	MaxTypedStreamChunk             = 64 << 10
	MaxTypedStreamWindow            = 1 << 20
)

type StreamOpen struct {
	Kind StreamKind `json:"kind"`
	Cols uint16     `json:"cols,omitempty"`
	Rows uint16     `json:"rows,omitempty"`
	Term string     `json:"term,omitempty"`
	// InitialWindow is receive credit granted by the opener to the acceptor.
	// The acceptor may send at most this many data bytes before receiving
	// StreamWindowUpdate credit from the opener.
	InitialWindow uint32 `json:"initial_window"`
}

type StreamAccepted struct {
	// InitialWindow is receive credit granted by the acceptor to the opener.
	InitialWindow uint32 `json:"initial_window"`
}

type StreamWindowUpdate struct {
	// Bytes adds send credit for the peer. Credit is additive but the runtime
	// must keep its effective per-stream window bounded by MaxTypedStreamWindow.
	Bytes uint32 `json:"bytes"`
}

type StreamClose struct {
	Reason string `json:"reason,omitempty"`
}

type StreamError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func ParseTypedStreamJSON(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("typed stream payload contains trailing JSON value")
		}
		return err
	}
	return nil
}

func ValidateStreamOpen(streamID uint32, open StreamOpen) error {
	if streamID == 0 {
		return errors.New("typed stream ID must be non-zero")
	}
	if open.Kind != StreamKindTerminal {
		return errors.New("unsupported typed stream kind")
	}
	if open.Cols == 0 || open.Rows == 0 {
		return errors.New("terminal stream size must be non-zero")
	}
	if open.InitialWindow == 0 || open.InitialWindow > MaxTypedStreamWindow {
		return errors.New("typed stream initial window is out of range")
	}
	return nil
}

func ValidateStreamData(streamID uint32, payload []byte) error {
	if streamID == 0 {
		return errors.New("typed stream ID must be non-zero")
	}
	if len(payload) == 0 || len(payload) > MaxTypedStreamChunk {
		return errors.New("typed stream data is out of range")
	}
	return nil
}

func ValidateStreamResize(streamID uint32, resize Resize) error {
	if streamID == 0 {
		return errors.New("typed stream ID must be non-zero")
	}
	if resize.Cols == 0 || resize.Rows == 0 {
		return errors.New("typed terminal resize must be non-zero")
	}
	return nil
}

func ValidateStreamWindowUpdate(streamID uint32, update StreamWindowUpdate) error {
	if streamID == 0 {
		return errors.New("typed stream ID must be non-zero")
	}
	if update.Bytes == 0 || update.Bytes > MaxTypedStreamWindow {
		return errors.New("typed stream window update is out of range")
	}
	return nil
}

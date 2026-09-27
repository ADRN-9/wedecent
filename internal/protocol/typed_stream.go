package protocol

import "errors"

type StreamKind string

const (
	StreamKindTerminal   StreamKind = "terminal"
	MaxTypedStreamWindow            = 1 << 20
)

type StreamOpen struct {
	Kind          StreamKind `json:"kind"`
	Cols          uint16     `json:"cols,omitempty"`
	Rows          uint16     `json:"rows,omitempty"`
	Term          string     `json:"term,omitempty"`
	InitialWindow uint32     `json:"initial_window"`
}

type StreamAccepted struct {
	InitialWindow uint32 `json:"initial_window"`
}

type StreamWindowUpdate struct {
	Bytes uint32 `json:"bytes"`
}

type StreamClose struct {
	Reason string `json:"reason,omitempty"`
}

type StreamError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
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

func ValidateStreamWindowUpdate(streamID uint32, update StreamWindowUpdate) error {
	if streamID == 0 {
		return errors.New("typed stream ID must be non-zero")
	}
	if update.Bytes == 0 || update.Bytes > MaxTypedStreamWindow {
		return errors.New("typed stream window update is out of range")
	}
	return nil
}

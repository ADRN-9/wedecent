package v1

import "context"

const MaxTerminalTypeBytes = 128

// TerminalStream is an opaque Core-owned logical terminal. Its ID is local to
// Core and is intentionally unrelated to the wire-level typed stream ID.
type TerminalStream struct {
	ID           string `json:"id"`
	ConnectionID string `json:"connection_id"`
}

type TerminalStreamOpenRequest struct {
	ConnectionID string `json:"connection_id"`
	Cols         uint16 `json:"cols"`
	Rows         uint16 `json:"rows"`
	Term         string `json:"term,omitempty"`
}

type TerminalStreamCloseRequest struct {
	ConnectionID string `json:"connection_id"`
	TerminalID   string `json:"terminal_id"`
}

type TerminalStreamReadRequest struct {
	ConnectionID string `json:"connection_id"`
	TerminalID   string `json:"terminal_id"`
	MaxBytes     int    `json:"max_bytes,omitempty"`
}

type TerminalStreamWriteRequest struct {
	ConnectionID string `json:"connection_id"`
	TerminalID   string `json:"terminal_id"`
	Data         []byte `json:"data"`
}

type TerminalStreamResizeRequest struct {
	ConnectionID string `json:"connection_id"`
	TerminalID   string `json:"terminal_id"`
	Cols         uint16 `json:"cols"`
	Rows         uint16 `json:"rows"`
}

// TerminalStreamService is the Core-owned multiplex terminal surface. Local IPC
// intentionally does not expose it until the protected bridge contract is wired.
type TerminalStreamService interface {
	OpenTerminalStream(context.Context, TerminalStreamOpenRequest) (TerminalStream, error)
	CloseTerminalStream(context.Context, TerminalStreamCloseRequest) error
	ReadTerminalStream(context.Context, TerminalStreamReadRequest) (TerminalReadResult, error)
	WriteTerminalStream(context.Context, TerminalStreamWriteRequest) error
	ResizeTerminalStream(context.Context, TerminalStreamResizeRequest) error
}

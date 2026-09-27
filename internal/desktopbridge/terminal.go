package desktopbridge

import (
	"context"
	"errors"
	"fmt"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const MaxDesktopIDBytes = 128

var ErrInvalidTerminalBridgeRequest = errors.New("desktop terminal bridge: invalid request")

type TerminalSource interface {
	Connect(context.Context, v1.ConnectRequest) (v1.Connection, error)
	Disconnect(context.Context, v1.DisconnectRequest) error
	ReadTerminal(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error)
	WriteTerminal(context.Context, v1.TerminalWriteRequest) error
	ResizeTerminal(context.Context, v1.TerminalResizeRequest) error
}

type TerminalStreamSource interface {
	v1.TerminalStreamService
}

type ConnectionSummary struct {
	ID       string             `json:"id"`
	DeviceID string             `json:"device_id"`
	State    v1.ConnectionState `json:"state"`
	Path     v1.ConnectionPath  `json:"path"`
}

type TerminalStreamSummary struct {
	ID           string `json:"id"`
	ConnectionID string `json:"connection_id"`
}

type TerminalReadSummary struct {
	Data   []byte `json:"data,omitempty"`
	Closed bool   `json:"closed"`
}

func Connect(ctx context.Context, source TerminalSource, deviceID string) (ConnectionSummary, error) {
	if err := validatePublicID(deviceID); err != nil {
		return ConnectionSummary{}, err
	}
	connection, err := source.Connect(ctx, v1.ConnectRequest{DeviceID: deviceID})
	if err != nil {
		return ConnectionSummary{}, err
	}
	if err := validatePublicID(connection.ID); err != nil {
		return ConnectionSummary{}, fmt.Errorf("%w: invalid connection id from Local Core", ErrInvalidTerminalBridgeRequest)
	}
	if connection.DeviceID != deviceID {
		return ConnectionSummary{}, fmt.Errorf("%w: mismatched device id from Local Core", ErrInvalidTerminalBridgeRequest)
	}
	return ConnectionSummary{
		ID:       connection.ID,
		DeviceID: connection.DeviceID,
		State:    connection.State,
		Path:     connection.Path,
	}, nil
}

func Disconnect(ctx context.Context, source TerminalSource, connectionID string) error {
	if err := validatePublicID(connectionID); err != nil {
		return err
	}
	return source.Disconnect(ctx, v1.DisconnectRequest{ConnectionID: connectionID})
}

func ReadTerminal(ctx context.Context, source TerminalSource, connectionID string) (TerminalReadSummary, error) {
	if err := validatePublicID(connectionID); err != nil {
		return TerminalReadSummary{}, err
	}
	result, err := source.ReadTerminal(ctx, v1.TerminalReadRequest{
		ConnectionID: connectionID,
		MaxBytes:     v1.MaxTerminalChunkBytes,
	})
	if err != nil {
		return TerminalReadSummary{}, err
	}
	return sanitizeTerminalRead(result)
}

func WriteTerminal(ctx context.Context, source TerminalSource, connectionID string, data []byte) error {
	if err := validatePublicID(connectionID); err != nil {
		return err
	}
	if err := validateTerminalData(data); err != nil {
		return err
	}
	return source.WriteTerminal(ctx, v1.TerminalWriteRequest{ConnectionID: connectionID, Data: data})
}

func ResizeTerminal(ctx context.Context, source TerminalSource, connectionID string, cols, rows uint16) error {
	if err := validatePublicID(connectionID); err != nil {
		return err
	}
	if err := validateTerminalDimensions(cols, rows); err != nil {
		return err
	}
	return source.ResizeTerminal(ctx, v1.TerminalResizeRequest{ConnectionID: connectionID, Cols: cols, Rows: rows})
}

func OpenTerminalStream(ctx context.Context, source TerminalStreamSource, connectionID string, cols, rows uint16, term string) (TerminalStreamSummary, error) {
	if err := validatePublicID(connectionID); err != nil {
		return TerminalStreamSummary{}, err
	}
	if err := validateTerminalDimensions(cols, rows); err != nil {
		return TerminalStreamSummary{}, err
	}
	if len(term) > v1.MaxTerminalTypeBytes {
		return TerminalStreamSummary{}, fmt.Errorf("%w: terminal type exceeds limit", ErrInvalidTerminalBridgeRequest)
	}
	stream, err := source.OpenTerminalStream(ctx, v1.TerminalStreamOpenRequest{
		ConnectionID: connectionID,
		Cols:         cols,
		Rows:         rows,
		Term:         term,
	})
	if err != nil {
		return TerminalStreamSummary{}, err
	}
	if err := validatePublicID(stream.ID); err != nil || stream.ConnectionID != connectionID {
		return TerminalStreamSummary{}, fmt.Errorf("%w: invalid terminal stream from Local Core", ErrInvalidTerminalBridgeRequest)
	}
	return TerminalStreamSummary{ID: stream.ID, ConnectionID: stream.ConnectionID}, nil
}

func CloseTerminalStream(ctx context.Context, source TerminalStreamSource, connectionID, terminalID string) error {
	if err := validateStreamIDs(connectionID, terminalID); err != nil {
		return err
	}
	return source.CloseTerminalStream(ctx, v1.TerminalStreamCloseRequest{ConnectionID: connectionID, TerminalID: terminalID})
}

func ReadTerminalStream(ctx context.Context, source TerminalStreamSource, connectionID, terminalID string) (TerminalReadSummary, error) {
	if err := validateStreamIDs(connectionID, terminalID); err != nil {
		return TerminalReadSummary{}, err
	}
	result, err := source.ReadTerminalStream(ctx, v1.TerminalStreamReadRequest{
		ConnectionID: connectionID,
		TerminalID:   terminalID,
		MaxBytes:     v1.MaxTerminalChunkBytes,
	})
	if err != nil {
		return TerminalReadSummary{}, err
	}
	return sanitizeTerminalRead(result)
}

func WriteTerminalStream(ctx context.Context, source TerminalStreamSource, connectionID, terminalID string, data []byte) error {
	if err := validateStreamIDs(connectionID, terminalID); err != nil {
		return err
	}
	if err := validateTerminalData(data); err != nil {
		return err
	}
	return source.WriteTerminalStream(ctx, v1.TerminalStreamWriteRequest{
		ConnectionID: connectionID,
		TerminalID:   terminalID,
		Data:         data,
	})
}

func ResizeTerminalStream(ctx context.Context, source TerminalStreamSource, connectionID, terminalID string, cols, rows uint16) error {
	if err := validateStreamIDs(connectionID, terminalID); err != nil {
		return err
	}
	if err := validateTerminalDimensions(cols, rows); err != nil {
		return err
	}
	return source.ResizeTerminalStream(ctx, v1.TerminalStreamResizeRequest{
		ConnectionID: connectionID,
		TerminalID:   terminalID,
		Cols:         cols,
		Rows:         rows,
	})
}

func sanitizeTerminalRead(result v1.TerminalReadResult) (TerminalReadSummary, error) {
	if len(result.Data) > v1.MaxTerminalChunkBytes {
		return TerminalReadSummary{}, fmt.Errorf("%w: oversized terminal output", ErrInvalidTerminalBridgeRequest)
	}
	return TerminalReadSummary{Data: result.Data, Closed: result.Closed}, nil
}

func validateStreamIDs(connectionID, terminalID string) error {
	if err := validatePublicID(connectionID); err != nil {
		return err
	}
	return validatePublicID(terminalID)
}

func validateTerminalData(data []byte) error {
	if len(data) == 0 || len(data) > v1.MaxTerminalChunkBytes {
		return fmt.Errorf("%w: terminal write must contain 1..%d bytes", ErrInvalidTerminalBridgeRequest, v1.MaxTerminalChunkBytes)
	}
	return nil
}

func validateTerminalDimensions(cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return fmt.Errorf("%w: terminal dimensions must be non-zero", ErrInvalidTerminalBridgeRequest)
	}
	return nil
}

func validatePublicID(value string) error {
	if len(value) == 0 || len(value) > MaxDesktopIDBytes {
		return fmt.Errorf("%w: invalid public id", ErrInvalidTerminalBridgeRequest)
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b < 0x21 || b > 0x7e {
			return fmt.Errorf("%w: invalid public id", ErrInvalidTerminalBridgeRequest)
		}
	}
	return nil
}

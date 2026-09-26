package desktopbridge

import (
	"context"
	"errors"
	"fmt"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const (
	MaxDesktopIDBytes = 128
)

var ErrInvalidTerminalBridgeRequest = errors.New("desktop terminal bridge: invalid request")

type TerminalSource interface {
	Connect(context.Context, v1.ConnectRequest) (v1.Connection, error)
	Disconnect(context.Context, v1.DisconnectRequest) error
	ReadTerminal(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error)
	WriteTerminal(context.Context, v1.TerminalWriteRequest) error
	ResizeTerminal(context.Context, v1.TerminalResizeRequest) error
}

type ConnectionSummary struct {
	ID       string             `json:"id"`
	DeviceID string             `json:"device_id"`
	State    v1.ConnectionState `json:"state"`
	Path     v1.ConnectionPath  `json:"path"`
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
	if len(result.Data) > v1.MaxTerminalChunkBytes {
		return TerminalReadSummary{}, fmt.Errorf("%w: oversized terminal output", ErrInvalidTerminalBridgeRequest)
	}
	return TerminalReadSummary{Data: result.Data, Closed: result.Closed}, nil
}

func WriteTerminal(ctx context.Context, source TerminalSource, connectionID string, data []byte) error {
	if err := validatePublicID(connectionID); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > v1.MaxTerminalChunkBytes {
		return fmt.Errorf("%w: terminal write must contain 1..%d bytes", ErrInvalidTerminalBridgeRequest, v1.MaxTerminalChunkBytes)
	}
	return source.WriteTerminal(ctx, v1.TerminalWriteRequest{
		ConnectionID: connectionID,
		Data:         data,
	})
}

func ResizeTerminal(ctx context.Context, source TerminalSource, connectionID string, cols, rows uint16) error {
	if err := validatePublicID(connectionID); err != nil {
		return err
	}
	if cols == 0 || rows == 0 {
		return fmt.Errorf("%w: terminal dimensions must be non-zero", ErrInvalidTerminalBridgeRequest)
	}
	return source.ResizeTerminal(ctx, v1.TerminalResizeRequest{
		ConnectionID: connectionID,
		Cols:         cols,
		Rows:         rows,
	})
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

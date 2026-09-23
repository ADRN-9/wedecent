package guiapp

import (
	"context"
	"errors"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type inputBoundCore struct {
	writes int
}

func (c *inputBoundCore) GetStatus(context.Context) (v1.Status, error) {
	return v1.Status{APIVersion: v1.Version}, nil
}

func (c *inputBoundCore) ListDevices(context.Context) ([]v1.Device, error) {
	return nil, nil
}

func (c *inputBoundCore) GetDevice(context.Context, v1.GetDeviceRequest) (v1.Device, error) {
	return v1.Device{}, errors.New("unused")
}

func (c *inputBoundCore) Connect(context.Context, v1.ConnectRequest) (v1.Connection, error) {
	return v1.Connection{
		ID:       "conn_bounds",
		DeviceID: "wd_peer0000000000",
		State:    v1.ConnectionStateConnected,
	}, nil
}

func (c *inputBoundCore) Disconnect(context.Context, v1.DisconnectRequest) error {
	return nil
}

func (c *inputBoundCore) ReadTerminal(context.Context, v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	return v1.TerminalReadResult{}, errors.New("unused")
}

func (c *inputBoundCore) WriteTerminal(_ context.Context, req v1.TerminalWriteRequest) error {
	c.writes++
	for i := range req.Data {
		req.Data[i] = 0
	}
	return nil
}

func (c *inputBoundCore) ResizeTerminal(context.Context, v1.TerminalResizeRequest) error {
	return nil
}

func TestControllerRejectsOversizedTerminalInputBeforeCoreCall(t *testing.T) {
	core := &inputBoundCore{}
	controller, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Connect(context.Background(), "wd_peer0000000000"); err != nil {
		t.Fatal(err)
	}

	oversized := make([]byte, v1.MaxTerminalChunkBytes+1)
	if err := controller.WriteTerminal(context.Background(), oversized); !errors.Is(err, ErrTerminalInputTooLarge) {
		t.Fatalf("write error = %v, want terminal input too large", err)
	}
	if core.writes != 0 {
		t.Fatalf("core write calls = %d, want 0", core.writes)
	}
}

func TestControllerAcceptsMaximumTerminalInputWithoutMutatingCaller(t *testing.T) {
	core := &inputBoundCore{}
	controller, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Connect(context.Background(), "wd_peer0000000000"); err != nil {
		t.Fatal(err)
	}

	input := make([]byte, v1.MaxTerminalChunkBytes)
	for i := range input {
		input[i] = 0x41
	}
	if err := controller.WriteTerminal(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if core.writes != 1 {
		t.Fatalf("core write calls = %d, want 1", core.writes)
	}
	for i, b := range input {
		if b != 0x41 {
			t.Fatalf("caller input mutated at %d", i)
		}
	}
}

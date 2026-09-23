// Package guiapp contains platform-neutral GUI state transitions over the
// Local Core v1 contract. It does not perform networking, trust, or crypto.
package guiapp

import (
	"context"
	"errors"
	"strings"
	"sync"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

var (
	ErrCoreRequired    = errors.New("gui app: core service is required")
	ErrInvalidDeviceID = errors.New("gui app: invalid device id")
	ErrSessionActive   = errors.New("gui app: a session is already active")
	ErrNoSession       = errors.New("gui app: no active session")
)

type Core interface {
	v1.StatusService
	v1.DeviceService
	v1.ConnectionService
	v1.TerminalService
}

type Snapshot struct {
	Status  v1.Status
	Devices []v1.Device
}

type Controller struct {
	core Core

	mu         sync.Mutex
	connecting bool
	closing    bool
	active     *v1.Connection
}

func New(core Core) (*Controller, error) {
	if core == nil {
		return nil, ErrCoreRequired
	}
	return &Controller{core: core}, nil
}

func (c *Controller) Refresh(ctx context.Context) (Snapshot, error) {
	status, err := c.core.GetStatus(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	devices, err := c.core.ListDevices(ctx)
	if err != nil {
		return Snapshot{Status: status}, err
	}
	publicDevices := make([]v1.Device, len(devices))
	for i, device := range devices {
		// The prototype only needs display identity. Keep endpoint and
		// fingerprint data out of GUI-owned state even though they are public.
		publicDevices[i] = v1.Device{ID: device.ID, Name: device.Name}
	}
	return Snapshot{Status: status, Devices: publicDevices}, nil
}

func (c *Controller) Connect(ctx context.Context, deviceID string) (v1.Connection, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return v1.Connection{}, ErrInvalidDeviceID
	}

	c.mu.Lock()
	if c.active != nil || c.connecting || c.closing {
		c.mu.Unlock()
		return v1.Connection{}, ErrSessionActive
	}
	c.connecting = true
	c.mu.Unlock()

	connection, err := c.core.Connect(ctx, v1.ConnectRequest{DeviceID: deviceID})

	c.mu.Lock()
	c.connecting = false
	if err == nil {
		copy := connection
		c.active = &copy
	}
	c.mu.Unlock()
	return connection, err
}

func (c *Controller) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	if c.active == nil || c.closing {
		c.mu.Unlock()
		return ErrNoSession
	}
	connectionID := c.active.ID
	c.closing = true
	c.mu.Unlock()

	err := c.core.Disconnect(ctx, v1.DisconnectRequest{ConnectionID: connectionID})

	c.mu.Lock()
	c.closing = false
	if err == nil && c.active != nil && c.active.ID == connectionID {
		c.active = nil
	}
	c.mu.Unlock()
	return err
}

func (c *Controller) ReadTerminal(ctx context.Context, maxBytes int) (v1.TerminalReadResult, error) {
	connectionID, err := c.activeConnectionID()
	if err != nil {
		return v1.TerminalReadResult{}, err
	}
	result, err := c.core.ReadTerminal(ctx, v1.TerminalReadRequest{ConnectionID: connectionID, MaxBytes: maxBytes})
	if err != nil {
		return v1.TerminalReadResult{}, err
	}
	if result.Closed {
		c.clearActive(connectionID)
	}
	return result, nil
}

func (c *Controller) WriteTerminal(ctx context.Context, data []byte) error {
	connectionID, err := c.activeConnectionID()
	if err != nil {
		return err
	}
	return c.core.WriteTerminal(ctx, v1.TerminalWriteRequest{
		ConnectionID: connectionID,
		Data:         append([]byte(nil), data...),
	})
}

func (c *Controller) ResizeTerminal(ctx context.Context, cols, rows uint16) error {
	connectionID, err := c.activeConnectionID()
	if err != nil {
		return err
	}
	return c.core.ResizeTerminal(ctx, v1.TerminalResizeRequest{ConnectionID: connectionID, Cols: cols, Rows: rows})
}

func (c *Controller) ActiveConnection() (v1.Connection, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil {
		return v1.Connection{}, false
	}
	return *c.active, true
}

func (c *Controller) activeConnectionID() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil || c.closing {
		return "", ErrNoSession
	}
	return c.active.ID, nil
}

func (c *Controller) clearActive(connectionID string) {
	c.mu.Lock()
	if c.active != nil && c.active.ID == connectionID {
		c.active = nil
	}
	c.mu.Unlock()
}

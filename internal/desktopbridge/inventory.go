package desktopbridge

import (
	"context"
	"errors"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

var ErrInventorySourceRequired = errors.New("desktop bridge: Local Core inventory source is required")

// InventorySource is intentionally read-only. Local Core remains authoritative
// for device identity, trust, routing, transport selection, and session state.
type InventorySource interface {
	ListDevices(context.Context) ([]v1.Device, error)
	GetTransportStatus(context.Context) ([]v1.TransportStatus, error)
}

// Device is the renderer-visible device summary. Fingerprints and endpoints are
// intentionally excluded so discovery/routing data cannot become UI-owned trust.
type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Transport is a renderer-visible availability badge. Detail is intentionally
// excluded because it is not part of the desktop trust or identity contract.
type Transport struct {
	Name      v1.TransportName `json:"name"`
	Available bool             `json:"available"`
}

type Inventory struct {
	Devices    []Device    `json:"devices"`
	Transports []Transport `json:"transports"`
}

func GetInventory(ctx context.Context, source InventorySource) (Inventory, error) {
	if source == nil {
		return Inventory{}, ErrInventorySourceRequired
	}
	devices, err := source.ListDevices(ctx)
	if err != nil {
		return Inventory{}, err
	}
	transports, err := source.GetTransportStatus(ctx)
	if err != nil {
		return Inventory{}, err
	}

	out := Inventory{
		Devices:    make([]Device, len(devices)),
		Transports: make([]Transport, len(transports)),
	}
	for i, device := range devices {
		out.Devices[i] = Device{ID: device.ID, Name: device.Name}
	}
	for i, transport := range transports {
		out.Transports[i] = Transport{Name: transport.Name, Available: transport.Available}
	}
	return out, nil
}

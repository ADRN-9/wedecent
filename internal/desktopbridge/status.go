// Package desktopbridge defines the narrow data contract exported from the
// existing Local Core client to the desktop presentation shell.
//
// It must not acquire transport, trust, routing, cryptographic, or session
// authority. Those responsibilities remain behind the Local Core boundary.
package desktopbridge

import (
	"context"
	"errors"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

var ErrStatusSourceRequired = errors.New("desktop bridge: Local Core status source is required")

// StatusSource is intentionally smaller than the Local Core service. The
// initial desktop bridge is read-only and can only observe sanitized status.
type StatusSource interface {
	GetStatus(context.Context) (v1.Status, error)
}

// Status is the complete renderer-visible status contract for this slice.
// Account identifiers, email addresses, fingerprints, endpoints, credentials,
// trust-store data, and transport details are intentionally excluded.
type Status struct {
	APIVersion string `json:"api_version"`
	SignedIn   bool   `json:"signed_in"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
}

func GetStatus(ctx context.Context, source StatusSource) (Status, error) {
	if source == nil {
		return Status{}, ErrStatusSourceRequired
	}
	status, err := source.GetStatus(ctx)
	if err != nil {
		return Status{}, err
	}
	return Status{
		APIVersion: status.APIVersion,
		SignedIn:   status.SignedIn,
		DeviceID:   status.DeviceID,
		DeviceName: status.DeviceName,
	}, nil
}

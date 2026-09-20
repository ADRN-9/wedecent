// Package localipc provides the same-user local transport used by the WeDecent
// Local Core API. It never opens an IP socket.
package localipc

import "errors"

var (
	// ErrUnsafeEndpoint means an existing local IPC path or its containing
	// directory does not satisfy the same-user security boundary.
	ErrUnsafeEndpoint = errors.New("core local ipc: unsafe endpoint")

	// ErrEndpointInUse means another local core listener already owns the
	// current user's endpoint.
	ErrEndpointInUse = errors.New("core local ipc: endpoint already in use")

	// ErrUnsupportedPlatform means no protected local transport is implemented
	// for the current operating system.
	ErrUnsupportedPlatform = errors.New("core local ipc: unsupported platform")
)

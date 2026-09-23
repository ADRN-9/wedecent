package coreapi

import "errors"

var (
	// ErrInvalidRouterPolicy means a requested policy is structurally invalid or
	// asks the current router runtime to enforce an unsupported policy field.
	ErrInvalidRouterPolicy = errors.New("coreapi: invalid router policy")

	// ErrRouterUnavailable means no authoritative router runtime can currently
	// service the request.
	ErrRouterUnavailable = errors.New("coreapi: router service unavailable")

	// ErrRouterOperation hides implementation-specific router-control failures
	// from the UI-facing IPC error surface.
	ErrRouterOperation = errors.New("coreapi: router operation failed")
)

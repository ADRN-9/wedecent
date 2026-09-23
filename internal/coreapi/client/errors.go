package client

import (
	"errors"

	"wedecent.com/wedecent/internal/coreapi/ipc"
)

var ErrUnavailable = errors.New("core client: unavailable")

// UnavailableStage identifies the bounded Local Core transport step that failed.
// It intentionally exposes no OS, path, pipe, or other raw transport detail.
type UnavailableStage uint8

const (
	UnavailableStageUnknown UnavailableStage = iota
	UnavailableStageDial
	UnavailableStageSetDeadline
	UnavailableStageWriteRequest
	UnavailableStageReadResponse
)

func (s UnavailableStage) String() string {
	switch s {
	case UnavailableStageDial:
		return "dial"
	case UnavailableStageSetDeadline:
		return "set_deadline"
	case UnavailableStageWriteRequest:
		return "write_request"
	case UnavailableStageReadResponse:
		return "read_response"
	default:
		return "unknown"
	}
}

// UnavailableError is a sanitized local transport failure. Errors continue to
// match ErrUnavailable so existing outage classification remains compatible.
type UnavailableError struct {
	Stage UnavailableStage
}

func (e *UnavailableError) Error() string {
	if e == nil {
		return ErrUnavailable.Error()
	}
	return ErrUnavailable.Error() + ": " + e.Stage.String()
}

func (e *UnavailableError) Unwrap() error { return ErrUnavailable }

// IsRemoteCode reports whether err is a sanitized Local Core protocol error
// with the given public code.
func IsRemoteCode(err error, code string) bool {
	var remote *RemoteError
	return errors.As(err, &remote) && remote.IsCode(code)
}

// IsConnectionGone is true only when Local Core authoritatively reports that
// the opaque connection ID no longer exists. Transport loss alone is not enough
// to make this decision.
func IsConnectionGone(err error) bool {
	return IsRemoteCode(err, ipc.ErrorConnectionNotFound)
}

// IsUnavailable reports errors that may be transient while Local Core is
// restarting or its protected IPC endpoint is temporarily unavailable.
func IsUnavailable(err error) bool {
	return errors.Is(err, ErrUnavailable) || IsRemoteCode(err, ipc.ErrorConnectionUnavailable)
}

// RequestMayHaveReachedCore reports whether a local transport failure occurred
// after request transmission may have started. Unknown ErrUnavailable wrappers
// are treated conservatively as potentially delivered.
func RequestMayHaveReachedCore(err error) bool {
	if !errors.Is(err, ErrUnavailable) {
		return false
	}
	var unavailable *UnavailableError
	if !errors.As(err, &unavailable) || unavailable == nil {
		return true
	}
	switch unavailable.Stage {
	case UnavailableStageDial, UnavailableStageSetDeadline:
		return false
	default:
		return true
	}
}

func unavailableError(stage UnavailableStage) error {
	return &UnavailableError{Stage: stage}
}

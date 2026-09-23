package client

import (
	"errors"
	"fmt"

	"wedecent.com/wedecent/internal/coreapi/ipc"
)

var ErrUnavailable = errors.New("core client: unavailable")

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

func unavailableError(operation string) error {
	return fmt.Errorf("%w: %s", ErrUnavailable, operation)
}

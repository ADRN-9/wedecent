package main

import (
	"context"
	"errors"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/coreapi/ipc"
)

// terminalWriteDefinitelyNotDelivered reports only outcomes that prove the
// terminal handle was never invoked for this request. Anything else is treated
// conservatively as delivery-ambiguous so the replay key remains pending.
func terminalWriteDefinitelyNotDelivered(err error) bool {
	if err == nil {
		return false
	}
	if !errors.Is(err, coreclient.ErrUnavailable) &&
		(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		var remote *coreclient.RemoteError
		if !errors.As(err, &remote) {
			// The typed client returns a plain context error only before request
			// transmission begins (for example cancellation while dialing).
			return true
		}
	}

	for _, code := range []string{
		ipc.ErrorInvalidParams,
		ipc.ErrorMethodNotFound,
		ipc.ErrorConnectionNotFound,
		ipc.ErrorConnectionUnavailable,
		ipc.ErrorTerminalUnavailable,
	} {
		if coreclient.IsRemoteCode(err, code) {
			return true
		}
	}
	return false
}

package routercontrol

import "errors"

var ErrLocalEndpointUnsupported = errors.New("routercontrol: local admin endpoint is unsupported on this platform")

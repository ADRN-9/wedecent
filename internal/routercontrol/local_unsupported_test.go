//go:build !windows && !linux

package routercontrol

import (
	"context"
	"errors"
	"testing"
)

func TestLocalRouterAdminEndpointFailsClosedWhenUnsupported(t *testing.T) {
	if listener, err := ListenLocal(); listener != nil || !errors.Is(err, ErrLocalEndpointUnsupported) {
		t.Fatalf("ListenLocal() = %v, %v", listener, err)
	}
	if conn, err := DialLocal(context.Background()); conn != nil || !errors.Is(err, ErrLocalEndpointUnsupported) {
		t.Fatalf("DialLocal() = %v, %v", conn, err)
	}
}

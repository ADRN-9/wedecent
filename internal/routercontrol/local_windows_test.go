//go:build windows

package routercontrol

import (
	"strings"
	"testing"
)

func TestWindowsRouterAdminPipeSecurityBoundary(t *testing.T) {
	if windowsRouterAdminPipe != `\\.\pipe\WeDecent.RouterAdmin.v1` {
		t.Fatalf("router admin pipe = %q", windowsRouterAdminPipe)
	}

	for _, principal := range []string{";;;SY)", ";;;BA)", ";;;AU)"} {
		if !strings.Contains(windowsRouterAdminSDDL, principal) {
			t.Fatalf("router admin SDDL missing %s: %q", principal, windowsRouterAdminSDDL)
		}
	}
	for _, forbidden := range []string{";;;WD)", ";;;AN)"} {
		if strings.Contains(windowsRouterAdminSDDL, forbidden) {
			t.Fatalf("router admin SDDL grants forbidden principal %s: %q", forbidden, windowsRouterAdminSDDL)
		}
	}
}

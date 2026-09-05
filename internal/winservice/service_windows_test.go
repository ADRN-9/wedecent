//go:build windows

package winservice

import "testing"

func TestStateName(t *testing.T) {
	cases := map[uint32]string{
		serviceStopped:      "stopped",
		serviceStartPending: "start-pending",
		serviceStopPending:  "stop-pending",
		serviceRunning:      "running",
	}
	for state, want := range cases {
		if got := stateName(state); got != want {
			t.Fatalf("stateName(%d) = %q, want %q", state, got, want)
		}
	}
}

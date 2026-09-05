package session

import (
	"testing"
	"time"

	"wedecent.com/wedecent/internal/protocol"
)

func TestWaitForPeerCloseReturnsOnCloseFrame(t *testing.T) {
	frames := make(chan protocol.Frame, 1)
	errs := make(chan error, 1)
	frames <- protocol.Frame{Type: protocol.TypeClose}

	start := time.Now()
	waitForPeerClose(frames, errs, time.Second)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("waitForPeerClose did not return promptly for close acknowledgement")
	}
}

func TestWaitForPeerCloseReturnsOnReadEnd(t *testing.T) {
	frames := make(chan protocol.Frame, 1)
	errs := make(chan error, 1)
	errs <- errTestPeerClosed{}

	start := time.Now()
	waitForPeerClose(frames, errs, time.Second)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("waitForPeerClose did not return promptly when peer connection ended")
	}
}

func TestWaitForPeerCloseTimesOut(t *testing.T) {
	frames := make(chan protocol.Frame)
	errs := make(chan error)
	timeout := 20 * time.Millisecond

	start := time.Now()
	waitForPeerClose(frames, errs, timeout)
	if elapsed := time.Since(start); elapsed < timeout {
		t.Fatalf("waitForPeerClose returned before timeout: %v", elapsed)
	}
}

type errTestPeerClosed struct{}

func (errTestPeerClosed) Error() string { return "peer closed" }

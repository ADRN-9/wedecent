package session

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestWaitForTerminalDrainCompletes(t *testing.T) {
	ptyReadDone := make(chan struct{})
	close(ptyReadDone)

	if err := waitForTerminalDrain(ptyReadDone, make(chan error), time.Second); err != nil {
		t.Fatalf("waitForTerminalDrain() error = %v, want nil", err)
	}
}

func TestWaitForTerminalDrainReturnsPeerError(t *testing.T) {
	want := errors.New("peer disconnected")
	readErrCh := make(chan error, 1)
	readErrCh <- want

	err := waitForTerminalDrain(make(chan struct{}), readErrCh, time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("waitForTerminalDrain() error = %v, want %v", err, want)
	}
}

func TestWaitForTerminalDrainTreatsNilPeerErrorAsEOF(t *testing.T) {
	readErrCh := make(chan error, 1)
	readErrCh <- nil

	err := waitForTerminalDrain(make(chan struct{}), readErrCh, time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("waitForTerminalDrain() error = %v, want EOF", err)
	}
}

func TestWaitForTerminalDrainTimesOut(t *testing.T) {
	start := time.Now()
	err := waitForTerminalDrain(make(chan struct{}), make(chan error), 20*time.Millisecond)
	if !errors.Is(err, errTerminalDrainTimeout) {
		t.Fatalf("waitForTerminalDrain() error = %v, want drain timeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waitForTerminalDrain() took %v, want bounded return", elapsed)
	}
}

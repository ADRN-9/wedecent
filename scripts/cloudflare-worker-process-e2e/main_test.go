package main

import (
	"errors"
	"fmt"
	"testing"
)

func testProcess(output string) *managedProcess {
	buffer := &lockedBuffer{}
	_, _ = buffer.Write([]byte(output))
	done := make(chan struct{})
	close(done)
	return &managedProcess{output: buffer, done: done}
}

func TestStartWithPortRetryRetriesAddressInUse(t *testing.T) {
	ports := []int{43943, 43944}
	allocated := 0
	started := 0

	process, port, err := startWithPortRetry(
		func() (int, error) {
			if allocated >= len(ports) {
				return 0, errors.New("unexpected extra port allocation")
			}
			value := ports[allocated]
			allocated++
			return value, nil
		},
		func(int) (*managedProcess, error) {
			started++
			return testProcess(""), nil
		},
		func(*managedProcess) error {
			if started == 1 {
				return fmt.Errorf("listen tcp 127.0.0.1:%d: bind: address already in use", ports[0])
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("startWithPortRetry() error = %v", err)
	}
	if port != ports[1] {
		t.Fatalf("selected port = %d, want %d", port, ports[1])
	}
	if process == nil || started != 2 || allocated != 2 {
		t.Fatalf("process=%v started=%d allocated=%d, want process and two attempts", process != nil, started, allocated)
	}
}

func TestStartWithPortRetryDoesNotRetryNonCollision(t *testing.T) {
	started := 0
	process, _, err := startWithPortRetry(
		func() (int, error) { return 43943, nil },
		func(int) (*managedProcess, error) {
			started++
			return testProcess(""), nil
		},
		func(*managedProcess) error { return errors.New("invalid Worker configuration") },
	)
	if err == nil || process != nil {
		t.Fatalf("startWithPortRetry() = (%v, %v), want failure", process, err)
	}
	if started != 1 {
		t.Fatalf("start attempts = %d, want 1 for non-collision failure", started)
	}
}

func TestStartWithPortRetryIsBounded(t *testing.T) {
	allocated := 0
	started := 0
	process, port, err := startWithPortRetry(
		func() (int, error) {
			allocated++
			return 44000 + allocated, nil
		},
		func(int) (*managedProcess, error) {
			started++
			return testProcess(""), nil
		},
		func(*managedProcess) error { return errors.New("bind: address already in use") },
	)
	if err == nil || process != nil || port != 0 {
		t.Fatalf("startWithPortRetry() = (%v, %d, %v), want bounded failure", process, port, err)
	}
	if allocated != maxPortStartAttempts || started != maxPortStartAttempts {
		t.Fatalf("allocated=%d started=%d, want %d bounded attempts", allocated, started, maxPortStartAttempts)
	}
}

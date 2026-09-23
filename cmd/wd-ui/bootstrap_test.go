package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type bootstrapCore struct {
	mu    sync.Mutex
	steps []error
	calls int
}

func (c *bootstrapCore) GetStatus(context.Context) (v1.Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.calls
	c.calls++
	if len(c.steps) == 0 {
		return v1.Status{}, nil
	}
	if index >= len(c.steps) {
		index = len(c.steps) - 1
	}
	return v1.Status{}, c.steps[index]
}

func (c *bootstrapCore) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

var testBootstrapConfig = coreBootstrapConfig{
	Timeout:      50 * time.Millisecond,
	ProbeTimeout: 5 * time.Millisecond,
	RetryMin:     time.Millisecond,
	RetryMax:     2 * time.Millisecond,
}

func TestEnsureLocalCoreAlreadyAvailableDoesNotLaunch(t *testing.T) {
	core := &bootstrapCore{}
	launched := false
	err := ensureLocalCore(context.Background(), core, func() (<-chan error, error) {
		launched = true
		return nil, nil
	}, testBootstrapConfig)
	if err != nil {
		t.Fatal(err)
	}
	if launched {
		t.Fatal("available core unexpectedly launched a sibling process")
	}
}

func TestEnsureLocalCoreLaunchesOnlyForTransportUnavailable(t *testing.T) {
	core := &bootstrapCore{steps: []error{coreclient.ErrUnavailable, coreclient.ErrUnavailable, nil}}
	launchCalls := 0
	done := make(chan error)
	err := ensureLocalCore(context.Background(), core, func() (<-chan error, error) {
		launchCalls++
		return done, nil
	}, testBootstrapConfig)
	if err != nil {
		t.Fatal(err)
	}
	if launchCalls != 1 {
		t.Fatalf("launch calls = %d, want 1", launchCalls)
	}
	if core.callCount() < 3 {
		t.Fatalf("status calls = %d, want at least 3", core.callCount())
	}
}

func TestEnsureLocalCoreDoesNotLaunchForRemoteUnavailable(t *testing.T) {
	remote := &coreclient.RemoteError{Code: ipc.ErrorConnectionUnavailable, Message: "connection unavailable"}
	core := &bootstrapCore{steps: []error{remote}}
	launched := false
	err := ensureLocalCore(context.Background(), core, func() (<-chan error, error) {
		launched = true
		return nil, nil
	}, testBootstrapConfig)
	if !errors.Is(err, remote) {
		t.Fatalf("error = %v, want remote error", err)
	}
	if launched {
		t.Fatal("protocol error unexpectedly launched a sibling process")
	}
}

func TestEnsureLocalCoreAcceptsConcurrentLaunchWinner(t *testing.T) {
	core := &bootstrapCore{steps: []error{coreclient.ErrUnavailable, coreclient.ErrUnavailable, nil}}
	done := make(chan error, 1)
	done <- errors.New("sibling lost named-pipe race")
	close(done)
	err := ensureLocalCore(context.Background(), core, func() (<-chan error, error) {
		return done, nil
	}, testBootstrapConfig)
	if err != nil {
		t.Fatalf("concurrent launch winner should make endpoint healthy: %v", err)
	}
}

func TestEnsureLocalCoreSanitizesLaunchFailure(t *testing.T) {
	core := &bootstrapCore{steps: []error{coreclient.ErrUnavailable}}
	err := ensureLocalCore(context.Background(), core, func() (<-chan error, error) {
		return nil, errors.New(`CreateProcess C:\private\wd-core.exe: access denied`)
	}, testBootstrapConfig)
	if !errors.Is(err, ErrCoreLaunch) {
		t.Fatalf("error = %v, want ErrCoreLaunch", err)
	}
	if err.Error() != ErrCoreLaunch.Error() {
		t.Fatalf("launch error leaked detail: %q", err)
	}
}

func TestEnsureLocalCoreTimesOutWithoutKillingLaunchedProcess(t *testing.T) {
	core := &bootstrapCore{steps: []error{coreclient.ErrUnavailable}}
	done := make(chan error)
	err := ensureLocalCore(context.Background(), core, func() (<-chan error, error) {
		return done, nil
	}, testBootstrapConfig)
	if !errors.Is(err, ErrCoreStartupTimeout) {
		t.Fatalf("error = %v, want ErrCoreStartupTimeout", err)
	}
	select {
	case <-done:
		t.Fatal("bootstrap closed or consumed ownership of process completion channel")
	default:
	}
}

func TestEnsureLocalCoreReportsExitedChildWhenEndpointNeverAppears(t *testing.T) {
	core := &bootstrapCore{steps: []error{coreclient.ErrUnavailable}}
	done := make(chan error, 1)
	done <- errors.New("core exited")
	close(done)
	err := ensureLocalCore(context.Background(), core, func() (<-chan error, error) {
		return done, nil
	}, testBootstrapConfig)
	if !errors.Is(err, ErrCoreLaunch) {
		t.Fatalf("error = %v, want ErrCoreLaunch", err)
	}
}

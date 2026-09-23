package main

import (
	"context"
	"errors"
	"time"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const (
	coreBootstrapTimeout = 8 * time.Second
	coreProbeTimeout     = 400 * time.Millisecond
	coreRetryMin         = 100 * time.Millisecond
	coreRetryMax         = 500 * time.Millisecond
)

var (
	ErrCoreLaunch         = errors.New("Local Core could not be started")
	ErrCoreStartupTimeout = errors.New("Local Core did not become available")
)

type coreStatusClient interface {
	GetStatus(context.Context) (v1.Status, error)
}

type coreLaunchFunc func() (<-chan error, error)

type coreBootstrapConfig struct {
	Timeout      time.Duration
	ProbeTimeout time.Duration
	RetryMin     time.Duration
	RetryMax     time.Duration
}

var defaultCoreBootstrapConfig = coreBootstrapConfig{
	Timeout:      coreBootstrapTimeout,
	ProbeTimeout: coreProbeTimeout,
	RetryMin:     coreRetryMin,
	RetryMax:     coreRetryMax,
}

func ensureLocalCore(parent context.Context, core coreStatusClient, launch coreLaunchFunc, cfg coreBootstrapConfig) error {
	if parent == nil {
		return context.Canceled
	}
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()

	err := probeCore(ctx, core, cfg.ProbeTimeout)
	if err == nil {
		return nil
	}
	if parentErr := parent.Err(); parentErr != nil {
		return parentErr
	}
	// Launch only when the local transport itself is unavailable. A sanitized
	// protocol error proves that a core is already answering and must not cause
	// a second process to be started.
	if !errors.Is(err, coreclient.ErrUnavailable) {
		return err
	}

	done, err := launch()
	if err != nil {
		return ErrCoreLaunch
	}

	backoff := cfg.RetryMin
	launchExited := false
	for {
		err = probeCore(ctx, core, cfg.ProbeTimeout)
		if err == nil {
			return nil
		}
		if parentErr := parent.Err(); parentErr != nil {
			return parentErr
		}
		if ctx.Err() != nil {
			if launchExited {
				return ErrCoreLaunch
			}
			return ErrCoreStartupTimeout
		}
		if !errors.Is(err, coreclient.ErrUnavailable) {
			return err
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			stopTimer(timer)
			if parentErr := parent.Err(); parentErr != nil {
				return parentErr
			}
			if launchExited {
				return ErrCoreLaunch
			}
			return ErrCoreStartupTimeout
		case <-done:
			stopTimer(timer)
			// Another concurrently launched core may have won the named-pipe
			// race, so a child exit is not failure until the endpoint also fails
			// to become healthy within the bounded bootstrap window.
			launchExited = true
			done = nil
		case <-timer.C:
		}

		if backoff < cfg.RetryMax {
			backoff *= 2
			if backoff > cfg.RetryMax {
				backoff = cfg.RetryMax
			}
		}
	}
}

func probeCore(parent context.Context, core coreStatusClient, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	_, err := core.GetStatus(ctx)
	return err
}

func stopTimer(timer *time.Timer) {
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

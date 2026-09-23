package main

import (
	"context"
	"errors"
	"sync"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/guiapp"
)

var (
	ErrConnectOutcomeUnknown       = errors.New("wd-ui: connection outcome is unknown")
	ErrTerminalWriteOutcomeUnknown = errors.New("wd-ui: terminal write outcome is unknown")
)

type coreRecoverFunc func(context.Context) error

type coreRecoveryCall struct {
	done chan struct{}
	err  error
}

// recoveringCore adds bounded process recovery around the existing typed Core
// client without changing Local Core protocol or session semantics.
//
// Read-only and idempotent operations may replay after recovery. Connect and
// terminal writes replay only when the typed transport stage proves request
// transmission had not started. Once a write may have begun, their result is
// reported as unknown instead of risking duplicate side effects.
type recoveringCore struct {
	inner   guiapp.Core
	recover coreRecoverFunc

	mu         sync.Mutex
	inFlight   *coreRecoveryCall
	generation uint64
}

var _ guiapp.Core = (*recoveringCore)(nil)

func newRecoveringCore(inner guiapp.Core, recover coreRecoverFunc) guiapp.Core {
	if inner == nil || recover == nil {
		return inner
	}
	return &recoveringCore{inner: inner, recover: recover}
}

func (c *recoveringCore) GetStatus(ctx context.Context) (v1.Status, error) {
	generation := c.recoveryGeneration()
	out, err := c.inner.GetStatus(ctx)
	if !c.shouldRecover(err) {
		return out, err
	}
	if err := c.recoverOnce(ctx, generation); err != nil {
		return v1.Status{}, err
	}
	return c.inner.GetStatus(ctx)
}

func (c *recoveringCore) ListDevices(ctx context.Context) ([]v1.Device, error) {
	generation := c.recoveryGeneration()
	out, err := c.inner.ListDevices(ctx)
	if !c.shouldRecover(err) {
		return out, err
	}
	if err := c.recoverOnce(ctx, generation); err != nil {
		return nil, err
	}
	return c.inner.ListDevices(ctx)
}

func (c *recoveringCore) GetDevice(ctx context.Context, req v1.GetDeviceRequest) (v1.Device, error) {
	generation := c.recoveryGeneration()
	out, err := c.inner.GetDevice(ctx, req)
	if !c.shouldRecover(err) {
		return out, err
	}
	if err := c.recoverOnce(ctx, generation); err != nil {
		return v1.Device{}, err
	}
	return c.inner.GetDevice(ctx, req)
}

func (c *recoveringCore) Connect(ctx context.Context, req v1.ConnectRequest) (v1.Connection, error) {
	generation := c.recoveryGeneration()
	out, err := c.inner.Connect(ctx, req)
	if !c.shouldRecover(err) {
		return out, err
	}

	mayHaveReached := coreclient.RequestMayHaveReachedCore(err)
	recoveryErr := c.recoverOnce(ctx, generation)
	if mayHaveReached {
		return out, unknownMutationError(ErrConnectOutcomeUnknown, err, recoveryErr)
	}
	if recoveryErr != nil {
		return out, recoveryErr
	}

	retryOut, retryErr := c.inner.Connect(ctx, req)
	if c.shouldRecover(retryErr) && coreclient.RequestMayHaveReachedCore(retryErr) {
		return retryOut, unknownMutationError(ErrConnectOutcomeUnknown, retryErr, nil)
	}
	return retryOut, retryErr
}

func (c *recoveringCore) Disconnect(ctx context.Context, req v1.DisconnectRequest) error {
	generation := c.recoveryGeneration()
	err := c.inner.Disconnect(ctx, req)
	if !c.shouldRecover(err) {
		return err
	}
	if err := c.recoverOnce(ctx, generation); err != nil {
		return err
	}
	return c.inner.Disconnect(ctx, req)
}

func (c *recoveringCore) ReadTerminal(ctx context.Context, req v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	generation := c.recoveryGeneration()
	out, err := c.inner.ReadTerminal(ctx, req)
	if !c.shouldRecover(err) {
		return out, err
	}
	if recoverErr := c.recoverOnce(ctx, generation); recoverErr != nil {
		return v1.TerminalReadResult{}, recoverErr
	}
	// The controller already owns terminal-read retries and session-loss
	// detection. Returning the original unavailable error preserves that flow
	// and avoids hiding a potentially consumed read response.
	return out, err
}

func (c *recoveringCore) WriteTerminal(ctx context.Context, req v1.TerminalWriteRequest) error {
	generation := c.recoveryGeneration()
	err := c.inner.WriteTerminal(ctx, req)
	if !c.shouldRecover(err) {
		return err
	}

	mayHaveReached := coreclient.RequestMayHaveReachedCore(err)
	recoveryErr := c.recoverOnce(ctx, generation)
	if mayHaveReached {
		return unknownMutationError(ErrTerminalWriteOutcomeUnknown, err, recoveryErr)
	}
	if recoveryErr != nil {
		return recoveryErr
	}

	retryErr := c.inner.WriteTerminal(ctx, req)
	if c.shouldRecover(retryErr) && coreclient.RequestMayHaveReachedCore(retryErr) {
		return unknownMutationError(ErrTerminalWriteOutcomeUnknown, retryErr, nil)
	}
	return retryErr
}

func (c *recoveringCore) ResizeTerminal(ctx context.Context, req v1.TerminalResizeRequest) error {
	generation := c.recoveryGeneration()
	err := c.inner.ResizeTerminal(ctx, req)
	if !c.shouldRecover(err) {
		return err
	}
	if err := c.recoverOnce(ctx, generation); err != nil {
		return err
	}
	return c.inner.ResizeTerminal(ctx, req)
}

func (c *recoveringCore) shouldRecover(err error) bool {
	return errors.Is(err, coreclient.ErrUnavailable)
}

func unknownMutationError(kind, transportErr, recoveryErr error) error {
	if recoveryErr != nil {
		return errors.Join(kind, transportErr, recoveryErr)
	}
	return errors.Join(kind, transportErr)
}

func (c *recoveringCore) recoveryGeneration() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

// recoverOnce coalesces concurrent recovery attempts. The generation observed
// before the failed API call prevents a stale ErrUnavailable from starting a
// second recovery after another caller has already restored Core. Waiting
// callers remain cancelable. If the leader's own context is canceled, another
// still-live caller may become the next leader because failed recoveries do not
// advance the generation.
func (c *recoveringCore) recoverOnce(ctx context.Context, observedGeneration uint64) error {
	if ctx == nil {
		return context.Canceled
	}

	for {
		c.mu.Lock()
		if c.generation != observedGeneration {
			c.mu.Unlock()
			return nil
		}
		if current := c.inFlight; current != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-current.done:
				if current.err == nil {
					return nil
				}
				if ctx.Err() == nil && (errors.Is(current.err, context.Canceled) || errors.Is(current.err, context.DeadlineExceeded)) {
					continue
				}
				return current.err
			}
		}
		current := &coreRecoveryCall{done: make(chan struct{})}
		c.inFlight = current
		c.mu.Unlock()

		recoveryErr := c.recover(ctx)

		c.mu.Lock()
		current.err = recoveryErr
		if recoveryErr == nil {
			c.generation++
		}
		if c.inFlight == current {
			c.inFlight = nil
		}
		close(current.done)
		c.mu.Unlock()
		return recoveryErr
	}
}

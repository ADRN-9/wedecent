package main

import (
	"context"
	"errors"
	"sync"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/guiapp"
)

type coreRecoverFunc func(context.Context) error

type coreRecoveryCall struct {
	done chan struct{}
	err  error
}

// recoveringCore adds bounded process recovery around the existing typed Core
// client without changing Local Core protocol or session semantics.
//
// Only replay-safe methods are retried after recovery. Connect and terminal
// writes may have reached Core before a transport failure, so replaying them
// could create a duplicate connection or duplicate terminal input.
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
	if c.shouldRecover(err) {
		// Do not replay: a lost response cannot prove the first connect failed.
		_ = c.recoverOnce(ctx, generation)
	}
	return out, err
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
	if c.shouldRecover(err) {
		// Do not replay: a lost response cannot prove the bytes were not written.
		_ = c.recoverOnce(ctx, generation)
	}
	return err
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

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/guiapp"
)

var (
	ErrConnectOutcomeUnknown       = errors.New("wd-ui: connection outcome is unknown")
	ErrTerminalWriteOutcomeUnknown = errors.New("wd-ui: terminal write outcome is unknown")
)

var (
	connectOperationCounter       atomic.Uint64
	terminalWriteOperationCounter atomic.Uint64
)

type coreRecoverFunc func(context.Context) error

type coreRecoveryCall struct {
	done chan struct{}
	err  error
}

type pendingTerminalWrite struct {
	dataDigest  [sha256.Size]byte
	operationID string
	expiresAt   time.Time
}

// recoveringCore adds bounded process recovery around the existing typed Core
// client without changing networking, trust, or session ownership. Connect and
// terminal writes carry stable operation IDs so Core can deduplicate replay.
type recoveringCore struct {
	inner   guiapp.Core
	recover coreRecoverFunc

	mu                        sync.Mutex
	inFlight                  *coreRecoveryCall
	generation                uint64
	pendingConnectDevice      string
	pendingConnectOperationID string
	pendingConnectExpiresAt   time.Time
	pendingTerminalWrites     map[string]pendingTerminalWrite
}

var _ guiapp.Core = (*recoveringCore)(nil)

func newRecoveringCore(inner guiapp.Core, recover coreRecoverFunc) guiapp.Core {
	if inner == nil || recover == nil {
		return inner
	}
	return &recoveringCore{
		inner:                 inner,
		recover:               recover,
		pendingTerminalWrites: make(map[string]pendingTerminalWrite),
	}
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
	prepared, err := c.prepareConnectRequest(req)
	if err != nil {
		return v1.Connection{}, err
	}

	generation := c.recoveryGeneration()
	out, err := c.inner.Connect(ctx, prepared)
	if !c.shouldRecover(err) {
		c.clearPendingConnect(prepared)
		return out, err
	}

	firstMayHaveReached := coreclient.RequestMayHaveReachedCore(err)
	recoveryErr := c.recoverOnce(ctx, generation)
	if recoveryErr != nil {
		if firstMayHaveReached {
			return out, unknownMutationError(ErrConnectOutcomeUnknown, err, recoveryErr)
		}
		c.clearPendingConnect(prepared)
		return out, recoveryErr
	}

	retryOut, retryErr := c.inner.Connect(ctx, prepared)
	if !c.shouldRecover(retryErr) {
		c.clearPendingConnect(prepared)
		return retryOut, retryErr
	}
	if firstMayHaveReached || coreclient.RequestMayHaveReachedCore(retryErr) {
		return retryOut, unknownMutationError(ErrConnectOutcomeUnknown, retryErr, nil)
	}
	c.clearPendingConnect(prepared)
	return retryOut, retryErr
}

func (c *recoveringCore) Disconnect(ctx context.Context, req v1.DisconnectRequest) error {
	generation := c.recoveryGeneration()
	err := c.inner.Disconnect(ctx, req)
	if !c.shouldRecover(err) {
		if err == nil || coreclient.IsConnectionGone(err) {
			c.clearPendingTerminalWrite(req.ConnectionID)
		}
		return err
	}
	if err := c.recoverOnce(ctx, generation); err != nil {
		return err
	}
	err = c.inner.Disconnect(ctx, req)
	if err == nil || coreclient.IsConnectionGone(err) {
		c.clearPendingTerminalWrite(req.ConnectionID)
	}
	return err
}

func (c *recoveringCore) ReadTerminal(ctx context.Context, req v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	generation := c.recoveryGeneration()
	out, err := c.inner.ReadTerminal(ctx, req)
	if !c.shouldRecover(err) {
		if (err == nil && out.Closed) || coreclient.IsConnectionGone(err) {
			c.clearPendingTerminalWrite(req.ConnectionID)
		}
		return out, err
	}
	if recoverErr := c.recoverOnce(ctx, generation); recoverErr != nil {
		return v1.TerminalReadResult{}, recoverErr
	}
	return out, err
}

func (c *recoveringCore) WriteTerminal(ctx context.Context, req v1.TerminalWriteRequest) error {
	prepared, err := c.prepareTerminalWriteRequest(req)
	if err != nil {
		return err
	}

	generation := c.recoveryGeneration()
	err = c.inner.WriteTerminal(ctx, prepared)
	if !c.shouldRecover(err) {
		if err == nil || terminalWriteDefinitelyNotDelivered(err) {
			c.clearPendingTerminalWriteRequest(prepared)
			return err
		}
		return unknownMutationError(ErrTerminalWriteOutcomeUnknown, err, nil)
	}

	firstMayHaveReached := coreclient.RequestMayHaveReachedCore(err)
	recoveryErr := c.recoverOnce(ctx, generation)
	if recoveryErr != nil {
		if firstMayHaveReached {
			return unknownMutationError(ErrTerminalWriteOutcomeUnknown, err, recoveryErr)
		}
		c.clearPendingTerminalWriteRequest(prepared)
		return recoveryErr
	}

	retryErr := c.inner.WriteTerminal(ctx, prepared)
	if !c.shouldRecover(retryErr) {
		if retryErr == nil {
			c.clearPendingTerminalWriteRequest(prepared)
			return nil
		}
		if firstMayHaveReached {
			// The first attempt may have delivered bytes to an older Core. Even
			// an authoritative no-delivery result from the recovered Core cannot
			// prove what happened before that recovery boundary.
			if coreclient.IsConnectionGone(retryErr) {
				c.clearPendingTerminalWriteRequest(prepared)
			}
			return unknownMutationError(ErrTerminalWriteOutcomeUnknown, retryErr, nil)
		}
		if terminalWriteDefinitelyNotDelivered(retryErr) {
			c.clearPendingTerminalWriteRequest(prepared)
			return retryErr
		}
		return unknownMutationError(ErrTerminalWriteOutcomeUnknown, retryErr, nil)
	}
	if firstMayHaveReached || coreclient.RequestMayHaveReachedCore(retryErr) {
		return unknownMutationError(ErrTerminalWriteOutcomeUnknown, retryErr, nil)
	}
	c.clearPendingTerminalWriteRequest(prepared)
	return retryErr
}

func (c *recoveringCore) ResizeTerminal(ctx context.Context, req v1.TerminalResizeRequest) error {
	generation := c.recoveryGeneration()
	err := c.inner.ResizeTerminal(ctx, req)
	if !c.shouldRecover(err) {
		if coreclient.IsConnectionGone(err) {
			c.clearPendingTerminalWrite(req.ConnectionID)
		}
		return err
	}
	if err := c.recoverOnce(ctx, generation); err != nil {
		return err
	}
	err = c.inner.ResizeTerminal(ctx, req)
	if coreclient.IsConnectionGone(err) {
		c.clearPendingTerminalWrite(req.ConnectionID)
	}
	return err
}

func (c *recoveringCore) shouldRecover(err error) bool {
	return errors.Is(err, coreclient.ErrUnavailable)
}

func (c *recoveringCore) prepareConnectRequest(req v1.ConnectRequest) (v1.ConnectRequest, error) {
	if req.OperationID != "" {
		return req, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pendingConnectOperationID != "" {
		if c.pendingConnectDevice != req.DeviceID || time.Now().After(c.pendingConnectExpiresAt) {
			return v1.ConnectRequest{}, ErrConnectOutcomeUnknown
		}
		req.OperationID = c.pendingConnectOperationID
		return req, nil
	}
	req.OperationID = nextConnectOperationID()
	c.pendingConnectDevice = req.DeviceID
	c.pendingConnectOperationID = req.OperationID
	c.pendingConnectExpiresAt = time.Now().Add(v1.ConnectOperationReplayWindow)
	return req, nil
}

func (c *recoveringCore) clearPendingConnect(req v1.ConnectRequest) {
	if req.OperationID == "" {
		return
	}
	c.mu.Lock()
	if c.pendingConnectOperationID == req.OperationID && c.pendingConnectDevice == req.DeviceID {
		c.pendingConnectDevice = ""
		c.pendingConnectOperationID = ""
		c.pendingConnectExpiresAt = time.Time{}
	}
	c.mu.Unlock()
}

func (c *recoveringCore) prepareTerminalWriteRequest(req v1.TerminalWriteRequest) (v1.TerminalWriteRequest, error) {
	if req.OperationID != "" {
		return req, nil
	}
	if req.ConnectionID == "" || len(req.Data) < 1 || len(req.Data) > v1.MaxTerminalChunkBytes {
		return req, nil
	}

	digest := sha256.Sum256(req.Data)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if pending, ok := c.pendingTerminalWrites[req.ConnectionID]; ok {
		if now.After(pending.expiresAt) || pending.dataDigest != digest {
			return v1.TerminalWriteRequest{}, ErrTerminalWriteOutcomeUnknown
		}
		req.OperationID = pending.operationID
		return req, nil
	}
	req.OperationID = nextTerminalWriteOperationID()
	c.pendingTerminalWrites[req.ConnectionID] = pendingTerminalWrite{
		dataDigest:  digest,
		operationID: req.OperationID,
		expiresAt:   now.Add(v1.TerminalWriteReplayWindow),
	}
	return req, nil
}

func (c *recoveringCore) clearPendingTerminalWriteRequest(req v1.TerminalWriteRequest) {
	if req.OperationID == "" {
		return
	}
	c.mu.Lock()
	if pending, ok := c.pendingTerminalWrites[req.ConnectionID]; ok && pending.operationID == req.OperationID {
		delete(c.pendingTerminalWrites, req.ConnectionID)
	}
	c.mu.Unlock()
}

func (c *recoveringCore) clearPendingTerminalWrite(connectionID string) {
	c.mu.Lock()
	delete(c.pendingTerminalWrites, connectionID)
	c.mu.Unlock()
}

func nextConnectOperationID() string {
	return fmt.Sprintf("op_%x_%x_%x", uint64(os.Getpid()), uint64(time.Now().UnixNano()), connectOperationCounter.Add(1))
}

func nextTerminalWriteOperationID() string {
	return fmt.Sprintf("tw_%x_%x_%x", uint64(os.Getpid()), uint64(time.Now().UnixNano()), terminalWriteOperationCounter.Add(1))
}

type mutationOutcomeUnknownError struct {
	kind        error
	operation   error
	recoveryErr error
}

func (e *mutationOutcomeUnknownError) Error() string {
	return errors.Join(e.kind, e.operation, e.recoveryErr).Error()
}

func (e *mutationOutcomeUnknownError) Unwrap() []error {
	out := make([]error, 0, 3)
	if e.kind != nil {
		out = append(out, e.kind)
	}
	if e.operation != nil {
		out = append(out, e.operation)
	}
	if e.recoveryErr != nil {
		out = append(out, e.recoveryErr)
	}
	return out
}

func (e *mutationOutcomeUnknownError) MutationOutcomeUnknown() bool {
	return e != nil
}

func unknownMutationError(kind, operationErr, recoveryErr error) error {
	return &mutationOutcomeUnknownError{
		kind:        kind,
		operation:   operationErr,
		recoveryErr: recoveryErr,
	}
}

func (c *recoveringCore) recoveryGeneration() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

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
